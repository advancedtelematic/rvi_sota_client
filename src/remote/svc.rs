//! The main service handler
//!
//! Parses incoming messages and delegates them to the appropriate individual message handlers,
//! passing on the results to the [`main_loop`](../main_loop/index.html)

use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

use rustc_serialize::{json, Decodable};
use time;

use event::{Event, UpdateId};
use event::inbound::InboundEvent;
use event::outbound::{UpdateReport, InstalledSoftware, UpdateResult};
use genivi::upstream::Upstream;

use super::parm::{NotifyParams, StartParams, ChunkParams, ChunkReceived, FinishParams};
use super::parm::{ReportParams, AbortParams, ParamHandler};
use super::dw::Transfers;

use super::jsonrpc;
use super::jsonrpc::{OkResponse, ErrResponse};
use super::rvi;

use configuration::ClientConfiguration;

/// Encodes the list of service URLs the client registered.
///
/// Needs to be extended to introduce new services.
#[derive(RustcEncodable, Clone)]
pub struct LocalServices {
    /// "Start Download" URL.
    pub start: String,
    /// "Chunk" URL.
    pub chunk: String,
    /// "Abort Download" URL.
    pub abort: String,
    /// "Finish Download" URL.
    pub finish: String,
    /// "Get All Packages" URL.
    pub getpackages: String,
}

impl LocalServices {
    /// Returns the VIN of this device.
    ///
    /// # Arguments
    /// * `vin_match`: The index, where to look for the VIN in the service URL.
    pub fn get_vin(&self, vin_match: i32) -> String {
        self.start.split("/").nth(vin_match as usize).unwrap().to_string()
    }
}

/// Encodes the service URLs, that the server provides.
#[derive(RustcDecodable, Clone)]
pub struct BackendServices {
    /// URL for the "Start Download" call.
    pub start: String,
    /// URL for the "Chunk Received" call.
    pub ack: String,
    /// URL for the "Installation Report" call.
    pub report: String,
    /// URL for the "Get All Packages" call.
    pub packages: String
}

#[derive(RustcEncodable, Clone)]
struct StartDownload {
    vin: String,
    update_id: UpdateId,
    services: LocalServices,
}

#[derive(RustcEncodable, Clone)]
struct InstalledSoftwareResult {
    vin: String,
    installed_software: InstalledSoftware
}

pub struct RemoteServices {
    pub vin: String,
    url: String,
    local_svcs: Option<LocalServices>,
    svcs: Option<BackendServices>
}

impl RemoteServices {
    pub fn new(url: String) -> RemoteServices {
        RemoteServices {
            vin: String::new(),
            url: url,
            local_svcs: None,
            svcs: None
        }
    }

    pub fn set_remote(&mut self, vin: String, svcs: LocalServices) {
        self.vin = vin;
        self.local_svcs = Some(svcs);
    }

    pub fn set(&mut self, svcs: BackendServices) {
        self.svcs = Some(svcs);
    }

    pub fn send_chunk_received(&self, m: ChunkReceived) -> Result<String, String> {
        self.svcs.iter().next().ok_or(format!("RemoteServices not set"))
            .and_then(|ref svcs| rvi::send_message(&self.url, m, &svcs.ack))
    }

    fn make_start_download(&self, id: UpdateId) -> StartDownload {
        StartDownload {
            vin: self.vin.clone(),
            services: self.local_svcs.iter().next().cloned().unwrap(),
            update_id: id
        }
    }
}

impl Upstream for RemoteServices {
    fn send_start_download(&mut self, id: UpdateId) -> Result<String, String> {
        self.svcs.iter().next().ok_or(format!("RemoteServices not set"))
            .and_then(|ref svcs| rvi::send_message(
                    &self.url,
                    self.make_start_download(id),
                    &svcs.start))
    }

    fn send_update_report(&mut self, m: UpdateReport) -> Result<String, String> {
        self.svcs.iter().next().ok_or(format!("RemoteServices not set"))
            .and_then(|ref svcs| rvi::send_message(
                    &self.url,
                    UpdateResult {
                        vin: self.vin.clone(),
                        update_report: m },
                    &svcs.report))
    }

    fn send_installed_software(&mut self, m: InstalledSoftware) -> Result<String, String> {
        self.svcs.iter().next().ok_or(format!("RemoteServices not set"))
            .and_then(|ref svcs| rvi::send_message(
                    &self.url,
                    InstalledSoftwareResult {
                        vin: self.vin.clone(),
                        installed_software: m },
                    &svcs.packages))
    }
}


/// Type that encodes a single service handler.
///
/// Holds the necessary state, like in-progress transfers, that are needed for handling incoming
/// messages and sending replies to RVI. Needs to be thread safe as
/// [`hyper`](../../../hyper/index.html) handles requests asynchronously.
pub struct ServiceHandler {
    /// A `Sender` that connects the handlers with the `main_loop`.
    sender: Mutex<Sender<Event>>,
    /// The currently in-progress `Transfer`s.
    transfers: Arc<Mutex<Transfers>>,
    /// The service URLs that the SOTA server advertised.
    remote_services: Arc<Mutex<RemoteServices>>,
    /// The full `Configuration` of sota_client.
    conf: ClientConfiguration
}

impl ServiceHandler {
    /// Create a new `ServiceHandler`.
    ///
    /// # Arguments
    /// * `transfers`: A `Transfers` object to store the in-progress `Transfer`s.
    /// * `sender`: A `Sender` to call back into the `main_loop`.
    /// * `url`: The full URL, where RVI can be reached.
    /// * `c`: The full `Configuration` of sota_client.
    pub fn new(sender: Sender<Event>,
               r: Arc<Mutex<RemoteServices>>,
               c: ClientConfiguration) -> ServiceHandler {
        let transfers = Arc::new(Mutex::new(Transfers::new(c.storage_dir.clone())));
        let tc = transfers.clone();
        c.timeout
            .map(|t| {
                let _ = thread::spawn(move || ServiceHandler::start_timer(tc.deref(), t));
                info!("Transfers timeout after {}", t)})
            .unwrap_or(info!("No timeout configured, transfers will never time out."));

        ServiceHandler {
            sender: Mutex::new(sender),
            transfers: transfers,
            remote_services: r,
            conf: c
        }
    }

    /// Starts a infinite loop to expire timed out transfers. Checks once a second for timed out
    /// transfers.
    ///
    /// # Arguments
    /// * `transfers`: Pointer to a `Transfers` object, that stores the transfers to be checked for
    ///   expired timeouts.
    /// * `timeout`: The timeout in seconds.
    pub fn start_timer(transfers: &Mutex<Transfers>,
                       timeout: i64) {
        loop {
            thread::sleep(Duration::from_secs(1));
            let mut transfers = transfers.lock().unwrap();
            transfers.prune(time::get_time().sec, timeout);
        }
    }

    /// Helper function to send a `Event` to the `main_loop`.
    ///
    /// # Arguments
    /// * `e`: `Event` to send.
    fn push_notify(&self, e: InboundEvent) {
        try_or!(self.sender.lock().unwrap().send(Event::Inbound(e)), return);
    }

    /// Create a message handler `D`, and let it process the `message`. If it returns a
    /// Event, forward it to the `main_loop`. Returns a `jsonrpc` response indicating
    /// success or failure.
    ///
    /// # Arguments
    /// * `message`: The message, that should be handled.
    fn handle_message_params<D>(&self, id: u64, message: &str)
        -> Result<OkResponse<i32>, ErrResponse>
        where D: Decodable + ParamHandler {
        json::decode::<jsonrpc::Request<rvi::Message<D>>>(&message)
            .map_err(|_| ErrResponse::invalid_params(id))
            .and_then(|p| {
                let handler = &p.params.parameters[0];
                handler.handle(&self.remote_services, &self.transfers)
                    .map_err(|_| ErrResponse::unspecified(p.id))
                    .map(|r| {
                        r.map(|m| self.push_notify(m));
                        OkResponse::new(p.id, None) })
            })
        }
}

impl rvi::ServiceHandler for ServiceHandler {
    fn handle_service(&self, id: u64, service: &str, message: &str)
        -> Result<OkResponse<i32>, ErrResponse> {
        match service {
            "/sota/notify" => self.handle_message_params::<NotifyParams>(id, message),
            "/sota/start" => self.handle_message_params::<StartParams>(id, message),
            "/sota/chunk" => self.handle_message_params::<ChunkParams>(id, message),
            "/sota/finish" => self.handle_message_params::<FinishParams>(id, message),
            "/sota/abort" => self.handle_message_params::<AbortParams>(id, message),
            "/sota/getpackages" => self.handle_message_params::<ReportParams>(id, message),
            _ => Err(ErrResponse::invalid_request(id))
        }
    }

    fn register_services<F: Fn(&str) -> String>(&self, reg: F) {
        reg("/sota/notify");
        let mut remote_svcs = self.remote_services.lock().unwrap();
        let svcs = LocalServices {
            start: reg("/sota/start"),
            chunk: reg("/sota/chunk"),
            abort: reg("/sota/abort"),
            finish: reg("/sota/finish"),
            getpackages: reg("/sota/getpackages")
        };
        remote_svcs.set_remote(svcs.get_vin(self.conf.vin_match), svcs);
    }
}
