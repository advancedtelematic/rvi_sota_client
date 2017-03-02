use chan::{Sender, Receiver, WaitGroup};
use std;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use time;

use datatype::{Auth, Command, Config, Error, Event, Ostree, OstreePackage, Package,
               UpdateReport, SignedManifest, UpdateRequestStatus as Status,
               UpdateResultCode, system_info};
use gateway::Interpret;
use http::{AuthClient, Client};
use authenticate::{pkcs12, oauth2};
use http::tls::init_tls_client;
use package_manager::PackageManager;
use rvi::Services;
use sota::Sota;
use uptane::Uptane;


/// An `Interpreter` loops over any incoming values, on receipt of which it
/// delegates to the `interpret` function which will respond with output values.
pub trait Interpreter<I, O> {
    fn interpret(&mut self, input: I, otx: &Sender<O>);

    fn run(&mut self, irx: Receiver<I>, otx: Sender<O>, wg: WaitGroup) {
        loop {
            let input   = irx.recv().expect("interpreter sender closed");
            let started = time::precise_time_ns();

            wg.add(1);
            trace!("interpreter starting: {}", started);
            self.interpret(input, &otx);
            trace!("interpreter stopping: {}", started);
            wg.done();
        }
    }
}


/// The `EventInterpreter` listens for `Event`s and optionally responds with
/// `Command`s that may be sent to the `CommandInterpreter`.
pub struct EventInterpreter {
    pub auth:     Auth,
    pub pacman:   PackageManager,
    pub auto_dl:  bool,
    pub sysinfo:  Option<String>,
}

impl Interpreter<Event, Command> for EventInterpreter {
    fn interpret(&mut self, event: Event, ctx: &Sender<Command>) {
        info!("EventInterpreter received: {}", event);

        match event {
            Event::Authenticated => {
                if self.pacman != PackageManager::Off {
                    self.pacman.installed_packages().map(|packages| {
                        ctx.send(Command::SendInstalledPackages(packages));
                    }).unwrap_or_else(|err| error!("couldn't send a list of packages: {}", err));
                }

                self.sysinfo.as_ref().map(|_| ctx.send(Command::SendSystemInfo));
            }

            Event::NotAuthenticated => {
                info!("Trying to authenticate again...");
                ctx.send(Command::Authenticate(self.auth.clone()));
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
                    if let Some(custom) = meta.custom {
                        match (meta.hashes.get("sha256"), custom.uri) {
                            (Some(commit), Some(uri)) => {
                                ctx.send(Command::OstreeInstall(OstreePackage {
                                    commit:      commit.clone(),
                                    refName:     refname,
                                    description: custom.ecuIdentifier,
                                    pullUri:     uri
                                }));
                            }
                            (_, None) => error!("no custom.uri field for target: {}", refname),
                            (None, _) => error!("couldn't get sha256 hash for target: {}", refname)
                        }
                    } else {
                        error!("couldn't get custom field for target: {}", refname);
                    }
                }
            }

            _ => ()
        }
    }
}


/// The `IntermediateInterpreter` wraps each incoming `Command` inside an
/// `Interpret` type with no response channel for sending to the `CommandInterpreter`.
pub struct IntermediateInterpreter;

impl Interpreter<Command, Interpret> for IntermediateInterpreter {
    fn interpret(&mut self, cmd: Command, itx: &Sender<Interpret>) {
        info!("IntermediateInterpreter received: {}", cmd);
        itx.send(Interpret { command: cmd, resp_tx: None });
    }
}


/// The `CommandMode` toggles the `Command` handling procedure.
pub enum CommandMode {
    Sota,
    Rvi(Box<Services>),
    Uptane(Option<Uptane>)
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
        info!("CommandInterpreter received: {}", interpret.command);
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
                    CommandMode::Uptane(None) => {
                        info!("initialising uptane mode");
                        let ref uuid   = self.config.device.uuid;
                        let mut uptane = Uptane::new(self.config.uptane.clone(), uuid.clone());
                        let branch     = Ostree::get_current_branch()?;
                        let signed     = branch.signed_version(uuid.clone());
                        let manifest   = SignedManifest::new(uuid.clone(), uuid.clone(), signed)?;
                        uptane.put_manifest(self.http.as_ref(), manifest)?;
                        self.mode = CommandMode::Uptane(Some(uptane));
                        Event::UptaneInitialised
                    }

                    CommandMode::Uptane(Some(ref mut uptane)) => {
                        let (_, ts_new) = uptane.get_timestamp(self.http.as_ref(), true)?;
                        if ts_new {
                            let (targets, _) = uptane.get_targets(self.http.as_ref(), true)?;
                            Event::UptaneTargetsUpdated(targets.targets)
                        } else {
                            Event::UptaneTimestampUpdated
                        }
                    }

                    _ => {
                        let mut updates = sota.get_update_requests()?;
                        if updates.is_empty() {
                            Event::NoUpdateRequests
                        } else {
                            updates.sort_by_key(|u| u.installPos);
                            Event::UpdatesReceived(updates)
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
                let tls  = self.config.tls.as_ref().expect("tls config required");
                let prov = self.config.provision.as_ref().expect("provision config required");
                if Path::new(&tls.p12_path).exists() {
                    panic!("tls.p12_path already exists: {}", tls.p12_path);
                }

                let url = tls.server.join("/devices");
                let id  = prov.device_id.as_ref().unwrap_or(&self.config.device.uuid);
                let bundle = pkcs12(url, id.clone(), prov.expiry_days, self.http.as_ref())?;
                let _ = File::create(&tls.p12_path)
                    .map(|mut file| file.write(&*bundle).expect("couldn't write pkcs12 bundle"))
                    .map_err(|err| panic!("couldn't open tls.p12_path for writing: {}", err));

                init_tls_client(self.config.tls_data(false));
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
