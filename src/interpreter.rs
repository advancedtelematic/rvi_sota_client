use chan::{Sender, Receiver};
use std;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use datatype::{Auth, Command, Config, EcuCustom, Error, Event, OperationResult,
               OstreePackage, Package, RoleName, UpdateReport, UpdateRequestStatus as Status,
               UpdateResultCode, Url, system_info};
use gateway::Interpret;
use http::{AuthClient, Client};
use authenticate::oauth2;
use package_manager::{Credentials, PackageManager};
use rvi::Services;
use sota::Sota;
use uptane::Uptane;


/// An `Interpreter` loops over any incoming values, on receipt of which it
/// delegates to the `interpret` function which will respond with output values.
pub trait Interpreter<I, O> {
    fn interpret(&mut self, input: I, otx: &Sender<O>);

    fn run(&mut self, irx: Receiver<I>, otx: Sender<O>) {
        loop {
            self.interpret(irx.recv().expect("interpreter sender closed"), &otx);
        }
    }
}


/// The `EventInterpreter` listens for `Event`s and may respond `Command`s.
pub struct EventInterpreter {
    pub loop_tx: Sender<Event>,
    pub auth:    Auth,
    pub pacman:  PackageManager,
    pub auto_dl: bool,
    pub sysinfo: Option<String>,
    pub treehub: Option<Url>,
}

impl Interpreter<Event, Command> for EventInterpreter {
    fn interpret(&mut self, event: Event, ctx: &Sender<Command>) {
        info!("EventInterpreter received: {}", event);

        match event {
            Event::Authenticated => {
                self.loop_tx.send(Event::InstalledPackagesNeeded);
                self.loop_tx.send(Event::SystemInfoNeeded);
            }

            Event::DownloadComplete(ref dl) if self.pacman != PackageManager::Off => {
                ctx.send(Command::StartInstall(dl.update_id.clone()));
            }

            Event::DownloadFailed(id, reason) => {
                let report = UpdateReport::single(format!("{}", id), UpdateResultCode::GENERAL_ERROR, reason);
                ctx.send(Command::SendUpdateReport(report));
            }

            Event::InstallComplete(report) | Event::InstallFailed(report) => {
                ctx.send(Command::SendUpdateReport(report));
            }

            Event::InstalledPackagesNeeded if self.pacman != PackageManager::Off => {
                match self.pacman.installed_packages() {
                    Ok(pkgs) => ctx.send(Command::SendInstalledPackages(pkgs)),
                    Err(err) => error!("couldn't send a list of packages: {}", err)
                }
            }

            Event::NotAuthenticated => {
                ctx.send(Command::Authenticate(self.auth.clone()));
            }

            Event::SystemInfoNeeded => {
                self.sysinfo.as_ref().map(|_| ctx.send(Command::SendSystemInfo));
            }

            Event::UpdatesReceived(requests) => {
                for request in requests {
                    let id = request.requestId.clone();
                    match request.status {
                        Status::Pending  if self.auto_dl => ctx.send(Command::StartDownload(id)),
                        Status::InFlight if self.pacman == PackageManager::Off => (),
                        Status::InFlight if self.pacman.is_installed(&request.packageId) => {
                            let report = UpdateReport::single(format!("{}", id), UpdateResultCode::OK, "".to_string());
                            ctx.send(Command::SendUpdateReport(report));
                        }
                        Status::InFlight => ctx.send(Command::StartDownload(id)),
                        _ => ()
                    }
                }
            }

            Event::UptaneTargetsUpdated(targets) => {
                let treehub  = self.treehub.as_ref().expect("uptane expects a treehub url");
                let packages = targets.iter().filter_map(|(refname, meta)| {
                    meta.hashes.get("sha256")
                        .or_else(|| { error!("couldn't get sha256 for {}", refname); None })
                        .map(|commit| {
                            let ref ecu = meta.custom.as_ref().expect("no custom field").ecuIdentifier;
                            OstreePackage::new(ecu.clone(), refname.clone(), commit.clone(), "".into(), treehub)
                        })
                }).collect::<Vec<_>>();
                ctx.send(Command::OstreeInstall(packages));
            }

            _ => ()
        }
    }
}


/// The `IntermediateInterpreter` listens for `Command`s and wraps them with a
/// response channel for sending to the `CommandInterpreter`.
#[derive(Default)]
pub struct IntermediateInterpreter {
    pub resp_tx: Option<Arc<Mutex<Sender<Event>>>>
}

impl Interpreter<Command, Interpret> for IntermediateInterpreter {
    fn interpret(&mut self, cmd: Command, itx: &Sender<Interpret>) {
        trace!("IntermediateInterpreter received: {}", &cmd);
        itx.send(Interpret { cmd: cmd, etx: self.resp_tx.clone() });
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

impl Interpreter<Interpret, Event> for CommandInterpreter {
    fn interpret(&mut self, interpret: Interpret, etx: &Sender<Event>) {
        info!("CommandInterpreter received: {}", &interpret.cmd);
        let outcome = match self.auth {
            Auth::None        |
            Auth::Token(_)    |
            Auth::Certificate => self.process_command(interpret.cmd, etx),

            Auth::Provision      |
            Auth::Credentials(_) => self.authenticate(interpret.cmd)
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
        interpret.etx.map(|tx| tx.lock().unwrap().send(final_ev));
    }
}

impl CommandInterpreter {
    fn process_command(&mut self, cmd: Command, etx: &Sender<Event>) -> Result<Event, Error> {
        let mut sota = Sota::new(&self.config, self.http.as_ref());

        let result = match cmd {
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
                        uptane.initialize(&*self.http)?;
                        let timestamp = uptane.get_director(&*self.http, RoleName::Timestamp)?;
                        if timestamp.is_new() {
                            let targets = uptane.get_director(&*self.http, RoleName::Targets)?;
                            Event::UptaneTargetsUpdated(targets.data.targets.unwrap_or(HashMap::new()))
                        } else {
                            Event::UptaneTimestampUpdated
                        }
                    }

                }
            }

            Command::ListInstalledPackages => {
                let mut packages: Vec<Package> = Vec::new();
                if self.config.device.package_manager != PackageManager::Off {
                    packages = self.config.device.package_manager.installed_packages()?;
                }
                Event::FoundInstalledPackages(packages)
            }

            Command::ListSystemInfo => {
                let cmd = self.config.device.system_info.as_ref().expect("system_info command not set");
                Event::FoundSystemInfo(system_info(&cmd)?)
            }

            Command::OstreeInstall(pkgs) => {
                let creds = self.get_credentials();
                if let CommandMode::Uptane(ref mut uptane) = self.mode {
                    uptane.ecu_versions = pkgs.iter().map(|pkg| {
                        let result = match pkg.install(&creds) {
                            Ok((code,  out)) => OperationResult::new(pkg.refName.clone(), code, out),
                            Err((code, out)) => OperationResult::new(pkg.refName.clone(), code, out),
                        };
                        pkg.ecu_version(Some(EcuCustom { operation_result: result }))
                    }).collect::<Vec<_>>();
                    uptane.send_manifest = true;
                }
                Event::InstalledPackagesNeeded
            }

            Command::SendInstalledPackages(packages) => {
                sota.send_installed_packages(&packages)?;
                Event::InstalledPackagesSent
            }

            Command::SendInstalledSoftware(sw) => {
                if let CommandMode::Rvi(ref rvi) = self.mode {
                    let _ = rvi.remote.lock().unwrap().send_installed_software(sw);
                }
                Event::InstalledSoftwareSent
            }

            Command::SendSystemInfo => {
                if let Some(ref cmd) = self.config.device.system_info {
                    sota.send_system_info(system_info(&cmd)?.into_bytes())?;
                }
                Event::SystemInfoSent
            }

            Command::SendUpdateReport(report) => {
                if let CommandMode::Rvi(ref rvi) = self.mode {
                    let _ = rvi.remote.lock().unwrap().send_update_report(report);
                } else {
                    sota.send_update_report(&report)?;
                }
                Event::InstalledPackagesNeeded
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

                    CommandMode::Sota => {
                        etx.send(Event::InstallingUpdate(id.clone()));
                        match sota.install_update(id, &self.get_credentials()) {
                            Ok(report)  => Event::InstallComplete(report),
                            Err(report) => Event::InstallFailed(report)
                        }
                    }

                    CommandMode::Uptane(_) => unimplemented!()
                }
            }

            Command::Shutdown => std::process::exit(0),
        };

        Ok(result)
    }

    fn authenticate(&mut self, cmd: Command) -> Result<Event, Error> {
        let result = match cmd {
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
        };

        Ok(result)
    }

    fn get_credentials(&self) -> Credentials {
        let token = if let Auth::Token(ref t) = self.auth {
            Some(t.access_token.clone())
        } else {
            None
        };

        let (ca, cert, pkey) = if let Some(ref tls) = self.config.tls {
            (Some(tls.ca_file.clone()), Some(tls.cert_file.clone()), Some(tls.pkey_file.clone()))
        } else {
            (None, None, None)
        };

        Credentials {
            access_token: token,
            ca_file:      ca,
            cert_file:    cert,
            pkey_file:    pkey,
        }
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use chan::{Sender, Receiver};
    use std::thread;
    use uuid::Uuid;

    use super::*;
    use datatype::{Auth, Command, Config, DownloadComplete, Event,
                   UpdateReport, UpdateResultCode};
    use gateway::Interpret;
    use http::test_client::TestClient;
    use package_manager::{PackageManager, assert_rx};


    fn new_interpreter(mut ci: CommandInterpreter) -> (Sender<Command>, Receiver<Event>) {
        let (etx, erx) = chan::sync::<Event>(0);
        let (ctx, crx) = chan::sync::<Command>(0);

        thread::spawn(move || loop {
            match crx.recv() {
                Some(cmd) => ci.interpret(Interpret { cmd: cmd, etx: None }, &etx),
                None      => break
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

        ctx.send(Command::StartDownload(Uuid::default()));
        assert_rx(erx, &[
            Event::DownloadingUpdate(Uuid::default()),
            Event::DownloadComplete(DownloadComplete {
                update_id:    Uuid::default(),
                update_image: format!("/tmp/{}", Uuid::default()),
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

        ctx.send(Command::StartInstall(Uuid::default()));
        assert_rx(erx, &[
            Event::InstallingUpdate(Uuid::default()),
            Event::InstallComplete(UpdateReport::single(format!("{}", Uuid::default()), UpdateResultCode::OK, "".to_string()))
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

        ctx.send(Command::StartInstall(Uuid::default()));
        assert_rx(erx, &[
            Event::InstallingUpdate(Uuid::default()),
            Event::InstallFailed(UpdateReport::single(format!("{}", Uuid::default()), UpdateResultCode::INSTALL_FAILED, "failed".to_string()))
        ]);
    }
}
