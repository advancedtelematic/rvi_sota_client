use chan;
use chan::{Sender, Receiver};
use std;
use std::borrow::Cow;

use datatype::{AccessToken, Auth, ClientId, ClientSecret, Command, Config,
               Error, Event, UpdateState, UpdateRequestId};
use gateway::Interpret;
use http::{AuthClient, Client};
use oauth2::authenticate;
use ota_plus::OTA;
use rvi::Services;


pub trait Interpreter<I, O> {
    fn interpret(&mut self, input: I, otx: &Sender<O>);

    fn run(&mut self, irx: Receiver<I>, otx: Sender<O>) {
        loop {
            self.interpret(irx.recv().expect("interpreter sender closed"), &otx);
        }
    }
}


pub struct EventInterpreter;

impl Interpreter<Event, Command> for EventInterpreter {
    fn interpret(&mut self, event: Event, ctx: &Sender<Command>) {
        info!("Event received: {}", event);
        match event {
            Event::Authenticated => {
                info!("Now authenticated.");
            }

            Event::NotAuthenticated => {
                info!("Trying to authenticate again...");
                ctx.send(Command::Authenticate(None));
            }

            _ => ()
        }
    }
}


pub struct CommandInterpreter;

impl Interpreter<Command, Interpret> for CommandInterpreter {
    fn interpret(&mut self, cmd: Command, itx: &Sender<Interpret>) {
        info!("Command received: {}", cmd);
        itx.send(Interpret { command: cmd, response_tx: None });
    }
}


pub struct GlobalInterpreter<'t> {
    pub config:      Config,
    pub token:       Option<Cow<'t, AccessToken>>,
    pub http_client: Box<Client>,
    pub rvi:         Option<Services>,
    pub loopback_tx: Sender<Interpret>,
}

impl<'t> Interpreter<Interpret, Event> for GlobalInterpreter<'t> {
    fn interpret(&mut self, interpret: Interpret, etx: &Sender<Event>) {
        info!("Interpreter started: {}", interpret.command);

        let (multi_tx, multi_rx) = chan::async::<Event>();
        let outcome = match (self.token.as_ref(), self.config.auth.is_none()) {
            (Some(_), _) | (_, true) => self.authenticated(interpret.command, multi_tx),
            _                        => self.unauthenticated(interpret.command, multi_tx)
        };

        let mut response_ev: Option<Event> = None;
        match outcome {
            Ok(_) => {
                for ev in multi_rx {
                    etx.send(ev.clone());
                    response_ev = Some(ev);
                }
                info!("Interpreter finished.");
            }

            Err(Error::Authorization(_)) => {
                let ev = Event::NotAuthenticated;
                etx.send(ev.clone());
                response_ev = Some(ev);
                error!("Interpreter authentication failed");
            }

            Err(err) => {
                let ev = Event::Error(format!("{}", err));
                etx.send(ev.clone());
                response_ev = Some(ev);
                error!("Interpreter failed: {}", err);
            }
        }

        let ev = response_ev.expect("no response event to send back");
        interpret.response_tx.map(|tx| tx.lock().unwrap().send(ev));
    }
}

impl<'t> GlobalInterpreter<'t> {
    fn authenticated(&self, cmd: Command, etx: Sender<Event>) -> Result<(), Error> {
        let mut ota = OTA::new(&self.config, self.http_client.as_ref());

        // always send at least one Event response
        match cmd {
            Command::AcceptUpdates(ref ids) => {
                for id in ids {
                    info!("Accepting ID: {}", id);
                    etx.send(Event::UpdateStateChanged(id.clone(), UpdateState::Downloading));
                    self.rvi.as_ref().map(|rvi| rvi.remote.lock().unwrap().send_start_download(id.clone()));
                    let report = try!(ota.install_package_update(id.clone(), &etx));
                    try!(ota.send_install_report(&report));
                    info!("Install Report for {}: {:?}", id, report);
                    try!(ota.update_installed_packages())
                }
            }

            Command::AbortUpdates(_) => {
                // TODO: PRO-1014
            }

            Command::Authenticate(_) => etx.send(Event::Ok),

            Command::GetPendingUpdates => {
                let mut updates = try!(ota.get_package_updates());
                if !updates.is_empty() {
                    updates.sort_by_key(|u| u.installPos);
                    info!("New package updates available: {:?}", updates);
                    let ids = updates.iter().map(|u| u.requestId.clone()).collect::<Vec<UpdateRequestId>>();
                    self.loopback_tx.send(Interpret { command: Command::AcceptUpdates(ids), response_tx: None });
                }
                etx.send(Event::Ok);
            }

            Command::ListInstalledPackages => {
                let pkgs = try!(self.config.device.package_manager.installed_packages());
                etx.send(Event::FoundInstalledPackages(pkgs));
            }

            Command::SendInstalledSoftware(installed) => {
                installed.map(|inst| {
                    info!("Sending Installed Software: {:?}", inst);
                    self.rvi.as_ref().map(|rvi| rvi.remote.lock().unwrap().send_installed_software(inst));
                });
            }

            Command::SendSystemInfo => {
                let info = try!(self.config.device.system_info.report());
                try!(ota.send_system_info(&info));
                etx.send(Event::Ok);
                info!("Posted system info to the server.")
            },

            Command::SendUpdateReport(report) => {
                report.map(|rep| {
                    info!("Sending Update Report: {:?}", rep);
                    self.rvi.as_ref().map(|rvi| rvi.remote.lock().unwrap().send_update_report(rep));
                });
            }

            Command::Shutdown => std::process::exit(0),

            Command::UpdateInstalledPackages => {
                try!(ota.update_installed_packages());
                etx.send(Event::Ok);
                info!("Posted installed packages to the server.")
            }
        }

        Ok(())
    }

    fn unauthenticated(&mut self, cmd: Command, etx: Sender<Event>) -> Result<(), Error> {
        match cmd {
            Command::Authenticate(_) => {
                let config = self.config.auth.clone().expect("trying to authenticate without auth config");
                self.set_client(Auth::Credentials(ClientId(config.client_id), ClientSecret(config.secret)));
                let server = config.server.join("/token").expect("couldn't build authentication url");
                let token  = try!(authenticate(server, self.http_client.as_ref()));
                self.set_client(Auth::Token(token.clone()));
                self.token = Some(token.into());
                etx.send(Event::Authenticated);
            }

            Command::AcceptUpdates(_)           |
            Command::AbortUpdates(_)            |
            Command::GetPendingUpdates          |
            Command::ListInstalledPackages      |
            Command::SendInstalledSoftware(_)   |
            Command::SendSystemInfo             |
            Command::SendUpdateReport(_)        |
            Command::UpdateInstalledPackages     => etx.send(Event::NotAuthenticated),

            Command::Shutdown => std::process::exit(0),
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
    use datatype::{AccessToken, Command, Config, Event, UpdateState};
    use gateway::Interpret;
    use http::test_client::TestClient;
    use package_manager::PackageManager;
    use package_manager::tpm::assert_rx;


    fn new_interpreter(replies: Vec<String>, pkg_mgr: PackageManager) -> (Sender<Command>, Receiver<Event>) {
        let (etx, erx) = chan::sync::<Event>(0);
        let (ctx, crx) = chan::sync::<Command>(0);
        let (itx, _)   = chan::sync::<Interpret>(0);

        thread::spawn(move || {
            let mut gi = GlobalInterpreter {
                config:      Config::default(),
                token:       Some(AccessToken::default().into()),
                http_client: Box::new(TestClient::from(replies)),
                rvi:         None,
                loopback_tx: itx,
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
        let pkg_mgr    = PackageManager::new_file(true);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

        ctx.send(Command::Authenticate(None));
        assert_rx(erx, &[Event::Ok]);
    }

    #[test]
    fn accept_updates() {
        let replies    = vec!["[]".to_string(); 10];
        let pkg_mgr    = PackageManager::new_file(true);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

        ctx.send(Command::AcceptUpdates(vec!["1".to_string(), "2".to_string()]));
        assert_rx(erx, &[
            Event::UpdateStateChanged("1".to_string(), UpdateState::Downloading),
            Event::UpdateStateChanged("1".to_string(), UpdateState::Installing),
            Event::UpdateStateChanged("1".to_string(), UpdateState::Installed),
            Event::UpdateStateChanged("2".to_string(), UpdateState::Downloading),
            Event::UpdateStateChanged("2".to_string(), UpdateState::Installing),
            Event::UpdateStateChanged("2".to_string(), UpdateState::Installed),
        ]);
    }

    #[test]
    fn failed_updates() {
        let replies    = vec!["[]".to_string(); 10];
        let pkg_mgr    = PackageManager::new_file(false);
        let (ctx, erx) = new_interpreter(replies, pkg_mgr);

        ctx.send(Command::AcceptUpdates(vec!["1".to_string()]));
        assert_rx(erx, &[Event::Error("IO error: No such file or directory (os error 2)".to_owned())]);
    }
}
