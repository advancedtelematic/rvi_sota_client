use chan;
use chan::Sender;
use serde::{Deserialize, Serialize};
use serde_json as json;
use std::thread;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time;

use datatype::{ChunkReceived, DownloadStarted, Event, InstalledSoftware, RviConfig,
               UpdateReport, UpdateRequestId, Url};
use rvi::{RpcErr, RpcOk, RpcRequest, Transfers};
use rvi::parameters::{Abort, Chunk, Finish, Notify, Parameter, Report, Start};


/// Hold references to RVI service endpoints, currently active `Transfers`, and
/// where to broadcast outcome `Event`s to.
#[derive(Clone)]
pub struct Services {
    pub remote:    Arc<Mutex<RemoteServices>>,
    pub sender:    Arc<Mutex<Sender<Event>>>,
    pub transfers: Arc<Mutex<Transfers>>,
}

impl Services {
    /// Set up a new RVI service handler, pruning any inactive `Transfer`s each second.
    pub fn new(rvi_cfg: RviConfig, device_id: String, sender: Sender<Event>) -> Self {
        let transfers = Arc::new(Mutex::new(Transfers::new(rvi_cfg.storage_dir)));
        rvi_cfg.timeout.map_or_else(|| info!("Transfers will never time out."), |timeout| {
            info!("Transfers timeout after {} seconds.", timeout);
            let transfers = transfers.clone();
            thread::spawn(move || {
                let tick = chan::tick(Duration::from_secs(1));
                loop {
                    let _ = tick.recv();
                    let mut transfers = transfers.lock().unwrap();
                    transfers.prune(time::get_time().sec, timeout);
                }
            });
        });

        Services {
            remote:    Arc::new(Mutex::new(RemoteServices::new(device_id, rvi_cfg.client))),
            sender:    Arc::new(Mutex::new(sender)),
            transfers: transfers,
        }
    }

    /// Register each RVI endpoint with the provided registration function which
    /// should return a `String` representation of the URL used to contact that
    /// service.
    pub fn register_services<F: Fn(&str) -> String>(&mut self, register: F) {
        let _ = register("/sota/notify");
        let mut remote = self.remote.lock().unwrap();
        remote.local   = Some(LocalServices {
            start:    register("/sota/start"),
            chunk:    register("/sota/chunk"),
            abort:    register("/sota/abort"),
            finish:   register("/sota/finish"),
            getpackages: register("/sota/getpackages")
        });
    }

    /// Handle an incoming message for a specific service endpoint.
    pub fn handle_service(&self, service: &str, id: u64, msg: &str) -> Result<RpcOk<i32>, RpcErr> {
        match service {
            "/sota/notify"      => self.handle_message::<Notify>(id, msg),
            "/sota/start"       => self.handle_message::<Start>(id, msg),
            "/sota/chunk"       => self.handle_message::<Chunk>(id, msg),
            "/sota/finish"      => self.handle_message::<Finish>(id, msg),
            "/sota/getpackages" => self.handle_message::<Report>(id, msg),
            "/sota/abort"       => self.handle_message::<Abort>(id, msg),
            _                   => Err(RpcErr::invalid_request(id, format!("unknown service: {}", service)))
        }
    }

    /// Parse the message as an `RpcRequest<RviMessage<Parameter>>` then delegate
    /// to the specific `Parameter.handle()` function, forwarding any returned
    /// `Event` to the `Services` sender.
    fn handle_message<P>(&self, id: u64, msg: &str) -> Result<RpcOk<i32>, RpcErr>
        where P: Parameter + Serialize + Deserialize
    {
        let request = json::from_str::<RpcRequest<RviMessage<P>>>(&msg)
            .map_err(|err| RpcErr::invalid_params(id, format!("couldn't decode message: {}", err)))?;
        let event = request.params.parameters[0].handle(&self.remote, &self.transfers)
            .map_err(|err| RpcErr::unspecified(request.id, format!("couldn't handle parameters: {}", err)))?;
        event.map(|ev| self.sender.lock().unwrap().send(ev));
        Ok(RpcOk::new(request.id, None))
    }
}


pub struct RemoteServices {
    pub device_id:  String,
    pub rvi_client: Url,
    pub local:      Option<LocalServices>,
    pub backend:    Option<BackendServices>
}

impl RemoteServices {
    pub fn new(device_id: String, rvi_client: Url) -> RemoteServices {
        RemoteServices { device_id: device_id, rvi_client: rvi_client, local: None, backend: None }
    }

    fn send_message<S: Serialize>(&self, body: S, addr: &str) -> Result<String, String> {
        RpcRequest::new("message", RviMessage::new(addr, vec![body], 60)).send(self.rvi_client.clone())
    }

    pub fn send_download_started(&self, update_id: UpdateRequestId) -> Result<String, String> {
        let backend = try!(self.backend.as_ref().ok_or("BackendServices not set"));
        let local   = try!(self.local.as_ref().ok_or("LocalServices not set"));
        let start   = DownloadStarted { device: self.device_id.clone(), update_id: update_id, services: local.clone() };
        self.send_message(start, &backend.start)
    }

    pub fn send_chunk_received(&self, chunk: ChunkReceived) -> Result<String, String> {
        let backend = try!(self.backend.as_ref().ok_or("BackendServices not set"));
        self.send_message(chunk, &backend.ack)
    }

    pub fn send_update_report(&self, report: UpdateReport) -> Result<String, String> {
        let backend = try!(self.backend.as_ref().ok_or("BackendServices not set"));
        let result  = UpdateReportResult { device: self.device_id.clone(), update_report: report };
        self.send_message(result, &backend.report)
    }

    pub fn send_installed_software(&self, installed: InstalledSoftware) -> Result<String, String> {
        let backend = try!(self.backend.as_ref().ok_or("BackendServices not set"));
        let result  = InstalledSoftwareResult { device_id: self.device_id.clone(), installed: installed };
        self.send_message(result, &backend.packages)
    }
}


#[derive(Clone, Deserialize, Serialize)]
pub struct LocalServices {
    pub start:    String,
    pub abort:    String,
    pub chunk:    String,
    pub finish:   String,
    pub getpackages: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct BackendServices {
    pub start:    String,
    pub ack:      String,
    pub report:   String,
    pub packages: String
}


#[derive(Deserialize, Serialize)]
struct UpdateReportResult {
    pub device:        String,
    pub update_report: UpdateReport
}

#[derive(Deserialize, Serialize)]
struct InstalledSoftwareResult {
    device_id: String,
    installed: InstalledSoftware
}


#[derive(Deserialize, Serialize)]
pub struct RviMessage<S: Serialize> {
    pub service_name: String,
    pub parameters:   Vec<S>,
    pub timeout:      Option<i64>
}

impl<S: Serialize> RviMessage<S> {
    pub fn new(service: &str, parameters: Vec<S>, expire_in: i64) -> RviMessage<S> {
        RviMessage {
            service_name: service.to_string(),
            parameters:   parameters,
            timeout:      Some((time::get_time() + time::Duration::seconds(expire_in)).sec)
        }
    }
}
