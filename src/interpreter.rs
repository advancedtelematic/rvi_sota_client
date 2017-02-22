use chan;
use chan::{Sender, Receiver, WaitGroup};
use std::{process, thread};
use std::ops::Deref;
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;
use time;

use datatype::{Auth, ClientCredentials, Command, Config, Error, Event,
               Package, UpdateReport, UpdateRequestStatus as Status, UpdateResultCode,
               Url, system_info};
use gateway::Interpret;
use http::{AuthClient, Client};
use oauth2::authenticate;
use http::tls::set_certificates;
use registration::register;
use package_manager::PackageManager;
use rvi::Services;
use sota::Sota;


/// An `Interpreter` loops over any incoming values, on receipt of which it
/// delegates to the `interpret` function which will respond with output values.
pub trait Interpreter<I, O> {
    fn interpret(&mut self, input: I, otx: &Sender<O>);

    fn run(&mut self, irx: Receiver<I>, otx: Sender<O>, wg: WaitGroup) {
        let cooldown = Duration::from_millis(100);

        loop {
            let input   = irx.recv().expect("interpreter sender closed");
            let started = time::precise_time_ns();

            wg.add(1);
            trace!("interpreter starting: {}", started);
            self.interpret(input, &otx);

            thread::sleep(cooldown); // let any further work commence
            trace!("interpreter stopping: {}", started);
            wg.done();
        }
    }
}


/// The `EventInterpreter` listens for `Event`s and optionally responds with
/// `Command`s that may be sent to the `CommandInterpreter`.
pub struct EventInterpreter {
    pub pacman:        PackageManager,
    pub auto_download: bool,
    pub sysinfo:       Option<String>,
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
                ctx.send(Command::Authenticate(None));
            }

            Event::UpdatesReceived(requests) => {
                for request in requests {
                    let id = request.requestId.clone();
                    match request.status {
                        Status::Pending if self.auto_download => {
                            ctx.send(Command::StartDownload(id));
                        },

                        Status::InFlight if self.pacman != PackageManager::Off => {
                            if self.pacman.is_installed(&request.packageId) {
                                let report = UpdateReport::single(id, UpdateResultCode::OK, "".to_string());
                                ctx.send(Command::SendUpdateReport(report));
                            } else {
                                ctx.send(Command::StartDownload(id));
                            }
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

            _ => ()
        }
    }
}


/// The `CommandInterpreter` wraps each incoming `Command` inside an `Interpret`
/// type with no response channel for sending to the `GlobalInterpreter`.
pub struct CommandInterpreter;

impl Interpreter<Command, Interpret> for CommandInterpreter {
    fn interpret(&mut self, cmd: Command, itx: &Sender<Interpret>) {
        info!("CommandInterpreter received: {}", cmd);
        itx.send(Interpret { command: cmd, response_tx: None });
    }
}


/// The `GlobalInterpreter` interprets the `Command` inside incoming `Interpret`
/// messages, broadcasting `Event`s globally and (optionally) sending the final
/// outcome `Event` to the `Interpret` response channel.
pub struct GlobalInterpreter {
    pub config:      Config,
    pub auth:        Auth,
    pub http_client: Box<Client>,
    pub rvi:         Option<Services>
}

impl<'t> Interpreter<Interpret, Event> for GlobalInterpreter {
    fn interpret(&mut self, interpret: Interpret, etx: &Sender<Event>) {
        info!("GlobalInterpreter received: {}", interpret.command);

        let (multi_tx, multi_rx) = chan::async::<Event>();

        let outcome = match self.auth {
            Auth::None => match self.config.auth {
                None    => self.authenticated(interpret.command, multi_tx),
                Some(_) => self.unauthenticated(interpret.command, multi_tx),
            },
            Auth::Credentials(_) => self.unauthenticated(interpret.command, multi_tx),
            Auth::Token(_)       => self.authenticated(interpret.command, multi_tx),
            Auth::Registration(_) => self.unauthenticated(interpret.command, multi_tx),
            Auth::Certificate => self.authenticated(interpret.command, multi_tx),
        };
        
        let mut response_ev: Option<Event> = None;
        match outcome {
            Ok(_) => {
                for ev in multi_rx {
                    etx.send(ev.clone());
                    response_ev = Some(ev);
                }
            }

            Err(Error::HttpAuth(resp)) => {
                error!("HTTP authorization failed: {}", resp);
                self.auth = Auth::None;
                let ev = Event::NotAuthenticated;
                etx.send(ev.clone());
                response_ev = Some(ev);
            }

            Err(err) => {
                let ev = Event::Error(format!("{}", err));
                etx.send(ev.clone());
                response_ev = Some(ev);
            }
        }

        let ev = response_ev.expect("no response event to send back");
        interpret.response_tx.map(|tx| tx.lock().unwrap().send(ev));
    }
}

impl<'t> GlobalInterpreter {
    fn authenticated(&self, cmd: Command, etx: Sender<Event>) -> Result<(), Error> {
        let mut sota = Sota::new(&self.config, self.http_client.as_ref());

        // always send at least one Event response
        match cmd {
            Command::Authenticate(_) => etx.send(Event::AlreadyAuthenticated),

            Command::GetUpdateRequests => {
                let mut updates = try!(sota.get_update_requests());
                if updates.is_empty() {
                    etx.send(Event::NoUpdateRequests);
                } else {
                    updates.sort_by_key(|u| u.installPos);
                    etx.send(Event::UpdatesReceived(updates));
                }
            }

            Command::ListInstalledPackages => {
                let mut packages: Vec<Package> = Vec::new();
                if self.config.device.package_manager != PackageManager::Off {
                    packages = try!(self.config.device.package_manager.installed_packages());
                }
                etx.send(Event::FoundInstalledPackages(packages));
            }

            Command::ListSystemInfo => {
                let cmd = self.config.device.system_info.as_ref().expect("system_info command not set");
                etx.send(Event::FoundSystemInfo(try!(system_info(&cmd))));
            }

            Command::SendInstalledPackages(packages) => {
                try!(sota.send_installed_packages(&packages));
                etx.send(Event::InstalledPackagesSent);
            }

            Command::SendInstalledSoftware(sw) => {
                if let Some(ref rvi) = self.rvi {
                    let _ = rvi.remote.lock().unwrap().send_installed_software(sw);
                }
                etx.send(Event::InstalledSoftwareSent);
            }

            Command::SendSystemInfo => {
                let cmd = self.config.device.system_info.as_ref().expect("system_info command not set");
                try!(sota.send_system_info(&try!(system_info(&cmd))));
                etx.send(Event::SystemInfoSent);
            }

            Command::SendUpdateReport(report) => {
                if let Some(ref rvi) = self.rvi {
                    let _ = rvi.remote.lock().unwrap().send_update_report(report);
                } else {
                    try!(sota.send_update_report(&report));
                }
                etx.send(Event::UpdateReportSent);
            }

            Command::StartDownload(id) => {
                etx.send(Event::DownloadingUpdate(id.clone()));
                if let Some(ref rvi) = self.rvi {
                    let _ = rvi.remote.lock().unwrap().send_download_started(id);
                } else {
                    let _ = sota.download_update(id.clone())
                        .map(|dl| etx.send(Event::DownloadComplete(dl)))
                        .map_err(|err| etx.send(Event::DownloadFailed(id, format!("{}", err))));
                }
            }

            Command::StartInstall(id) => {
                etx.send(Event::InstallingUpdate(id.clone()));
                let token = match self.auth {
                    Auth::Token(ref t) => Some(t),
                    _ => None,
                };
                let _ = sota.install_update(token, id)
                    .map(|report| etx.send(Event::InstallComplete(report)))
                    .map_err(|report| etx.send(Event::InstallFailed(report)));
            }

            Command::Shutdown => process::exit(0),
        }

        Ok(())
    }

    fn auth_credentials(&mut self, server: Url, client_id: String, client_secret: String,
                        certificates_path: Option<&str>, device_p12_path: Option<&str>,
                        device_p12_password: &str) -> Result<(), Error> {
        set_certificates(certificates_path, device_p12_path, device_p12_password);

        self.set_client(Auth::Credentials(ClientCredentials {
            client_id:     client_id,
            client_secret: client_secret,
        }));
        let token = try!(authenticate(server.join("/token"), self.http_client.as_ref()));
        self.set_client(Auth::Token(token.clone()));
        self.auth = Auth::Token(token.into());
        Ok(())
    }

    fn auth_certificate(&mut self, server: Url, client_id: String, expires_in: u32,
                        certificates_path: Option<&str>, auth_p12_path: &str, auth_p12_password: &str,
                        device_p12_path: Option<&str>, device_p12_password: &str) -> Result<(), Error> {
        set_certificates(certificates_path, Some(auth_p12_path), auth_p12_password);
        let access_certificate = try!(register(server.join("/devices"),
                                               client_id, expires_in,
                                               self.http_client.as_ref()));
        let mut file = OpenOptions::new().read(true).write(true).open(device_p12_path.unwrap())
            .map_err(|err| panic!("couldn't open file: {}", err)).unwrap();
        file.write(&*access_certificate).expect("Error writing file");
        set_certificates(certificates_path, device_p12_path, device_p12_password);
        self.auth = Auth::Certificate;
        Ok(())
    }
    
    fn unauthenticated(&mut self, cmd: Command, etx: Sender<Event>) -> Result<(), Error> {
        let device_config = self.config.device.clone();

        match cmd {
            Command::Authenticate(None) => {
                let auth_config = self.config.auth.clone().expect("trying to authenticate without auth config");
                if auth_config.client_secret.is_some() {
                    try!(self.auth_credentials(auth_config.server, auth_config.client_id,
                                               auth_config.client_secret.unwrap(),
                                               device_config.certificates_path.as_ref().map(Deref::deref),device_config.p12_path.as_ref().map(Deref::deref),
                                               &device_config.p12_password));
                } else {
                    let device_config = self.config.device.clone();
                    try!(self.auth_certificate(auth_config.server, auth_config.client_id,
                                               auth_config.expires_in.unwrap(),
                                               device_config.certificates_path.as_ref().map(Deref::deref),
                                               auth_config.p12_path.unwrap().as_ref(), &auth_config.p12_password.unwrap(),
                                               device_config.p12_path.as_ref().map(Deref::deref),
                                               &device_config.p12_password));
                }
            }
            Command::Authenticate(Some(Auth::Credentials(client_credentials))) =>
            {
                let auth_config = self.config.auth.clone().expect("trying to authenticate without auth config");
                try!(self.auth_credentials(auth_config.server, client_credentials.client_id, client_credentials.client_secret,
                                           device_config.certificates_path.as_ref().map(Deref::deref),
                                           device_config.p12_path.as_ref().map(Deref::deref),
                                           &device_config.p12_password));
            }
            Command::Authenticate(Some(Auth::Registration(registration_credentials))) => {
                let auth_config = self.config.auth.clone().expect("trying to authenticate without auth config");
                try!(self.auth_certificate(auth_config.server, registration_credentials.client_id,
                                           auth_config.expires_in.unwrap(),
                                           device_config.certificates_path.as_ref().map(Deref::deref),
                                           auth_config.p12_path.unwrap().as_ref(), &auth_config.p12_password.unwrap(),
                                           device_config.p12_path.as_ref().map(Deref::deref),
                                           &device_config.p12_password));
                etx.send(Event::Authenticated);
            }

            Command::Shutdown => process::exit(0),

            _ => etx.send(Event::NotAuthenticated)
        }

        Ok(())
    }

    fn set_client(&mut self, auth: Auth) {
        if !self.http_client.is_testing() {
            self.http_client = Box::new(AuthClient::from(auth));
        }
    }
}


#[cfg(test)]
mod tests {
    use chan;
    use chan::{Sender, Receiver};
    use std::thread;

    use super::*;
    use datatype::{Command, Config, DownloadComplete, Event,
                   UpdateReport, UpdateResultCode};
    use gateway::Interpret;
    use http::test_client::TestClient;
    use package_manager::PackageManager;
    use package_manager::tpm::assert_rx;


    fn new_interpreter(replies: Vec<String>, pkg_mgr: PackageManager) -> (Sender<Command>, Receiver<Event>) {
        let (etx, erx) = chan::sync::<Event>(0);
        let (ctx, crx) = chan::sync::<Command>(0);

        thread::spawn(move || {
            let mut gi = GlobalInterpreter {
                config:      Config::default(),
                auth:        Auth::None,
                http_client: Box::new(TestClient::from(replies)),
                rvi:         None
            };
            gi.config.device.package_manager = pkg_mgr;

            loop {
                match crx.recv() {
                    Some(cmd) => gi.interpret(Interpret { command: cmd, response_tx: None }, &etx),
                    None      => break
                }
            }
        });

        (ctx, erx)
    }

    #[test]
    fn already_authenticated() {
        let replies    = Vec::new();
        let pkg_mgr    = PackageManager::new_tpm(true);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

        ctx.send(Command::Authenticate(None));
        assert_rx(erx, &[Event::AlreadyAuthenticated]);
    }

    #[test]
    fn download_updates() {
        let replies    = vec!["[]".to_string(); 10];
        let pkg_mgr    = PackageManager::new_tpm(true);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

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
        let replies    = vec!["[]".to_string(); 10];
        let pkg_mgr    = PackageManager::new_tpm(true);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

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
        let replies    = vec!["[]".to_string(); 10];
        let pkg_mgr    = PackageManager::new_tpm(false);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

        ctx.send(Command::StartInstall("1".to_string()));
        assert_rx(erx, &[
            Event::InstallingUpdate("1".to_string()),
            Event::InstallFailed(
                UpdateReport::single("1".to_string(), UpdateResultCode::INSTALL_FAILED, "failed".to_string())
            )
        ]);
    }
}
