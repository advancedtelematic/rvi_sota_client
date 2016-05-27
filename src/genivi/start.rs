//! Main loop, starting the worker threads and wiring up communication channels between them.

use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use configuration::Configuration;
use configuration::DBusConfiguration;
use event::Event;
use event::inbound::InboundEvent;
use event::outbound::OutBoundEvent;
use http::remote::HttpRemote;
use http::hyper::Hyper;
use http::update_poller;
use remote::svc::{RemoteServices, ServiceHandler};
use remote::rvi;
use super::upstream::Upstream;

pub fn handle<U: Upstream + Sized>(cfg: &DBusConfiguration, rx: Receiver<Event>, upstream: Arc<Mutex<U>>) {
    loop {
        match rx.recv().unwrap() {
            Event::Inbound(i) => match i {
                InboundEvent::UpdateAvailable(e) => {
                    info!("UpdateAvailable");
                    super::swm::send_update_available(&cfg, e);
                },
                InboundEvent::DownloadComplete(e) => {
                    info!("DownloadComplete");
                    super::swm::send_download_complete(&cfg, e);
                },
                InboundEvent::GetInstalledSoftware(e) => {
                    info!("GetInstalledSoftware");
                    let _ = super::swm::send_get_installed_software(&cfg, e)
                        .and_then(|e| {
                            upstream.lock().unwrap().send_installed_software(e)
                                .map_err(|e| error!("{}", e)) });
                }
            },
            Event::OutBound(o) => match o {
                OutBoundEvent::InitiateDownload(e) => {
                    info!("InitiateDownload");
                    let _ = upstream.lock().unwrap().send_start_download(e);
                },
                OutBoundEvent::AbortDownload(_) => info!("AbortDownload"),
                OutBoundEvent::UpdateReport(e) => {
                    info!("UpdateReport");
                    let _ = upstream.lock().unwrap().send_update_report(e);
                }
            }
        }
    }
}

fn dbus_handler<U: Upstream + Sized>(conf: &Configuration, tx: Sender<Event>, rx: Receiver<Event>, upstream: Arc<Mutex<U>>) {
    let dbus_receiver = super::sc::Receiver::new(conf.dbus.clone(), tx);
    thread::spawn(move || dbus_receiver.start());
    handle(&conf.dbus, rx, upstream);
}


/// Main loop, starting the worker threads and wiring up communication channels between them.
///
/// # Arguments
/// * `conf`: A pointer to a `Configuration` object see the [documentation of the configuration
///   crate](../configuration/index.html).
/// * `rvi_url`: The URL, where RVI can be found, with the protocol.
/// * `edge_url`: The `host:port` combination where the client should bind and listen for incoming
///   RVI calls.
pub fn start(conf: &Configuration, rvi_url: String, edge_url: String) {
    // Main message channel from RVI and DBUS
    let (tx, rx): (Sender<Event>, Receiver<Event>) = channel();

    if conf.client.http {
        // HTTP handler
        update_poller::start(conf.server.clone(), tx.clone());
        let upstream = Arc::new(Mutex::new(HttpRemote::new(conf.server.clone(), Hyper::new(), tx.clone())));
        dbus_handler(&conf, tx.clone(), rx, upstream);
    } else {
        // RVI edge handler
        let remote_svcs = Arc::new(Mutex::new(RemoteServices::new(rvi_url.clone())));
        let handler = ServiceHandler::new(tx.clone(), remote_svcs.clone(), conf.client.clone());
        let rvi_edge = rvi::ServiceEdge::new(rvi_url.clone(), edge_url, handler);
        rvi_edge.start();

        dbus_handler(&conf, tx.clone(), rx, remote_svcs);
    }
}
