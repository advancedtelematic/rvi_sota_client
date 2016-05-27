use std::sync::mpsc::Sender;
use genivi::upstream::Upstream;
use configuration::ServerConfiguration;
use http::HttpClient;
use http::api_client::{update_packages, download_package_update, send_install_report};
use event::outbound::{InstalledSoftware, UpdateReport};
use event::inbound::{DownloadComplete, InboundEvent};
use event::Event;
use event::UpdateId;

pub struct HttpRemote<C: HttpClient> {
    config: ServerConfiguration,
    client: C,
    tx: Sender<Event>
}

impl<C: HttpClient> HttpRemote<C> {
    pub fn new(config: ServerConfiguration, client: C, tx: Sender<Event>) -> HttpRemote<C> {
        HttpRemote { config: config, client: client, tx: tx }
    }
}

impl<C: HttpClient> Upstream for HttpRemote<C> {
    fn send_installed_software(&mut self, m: InstalledSoftware) -> Result<String, String> {
        update_packages(&self.config, &mut self.client, &m.packages)
            .map(|_| "ok".to_string())
            .map_err(|e| format!("{}", e))
    }

    fn send_start_download(&mut self, id: UpdateId) -> Result<String, String> {
        download_package_update(&self.config, &mut self.client, &id)
            .map_err(|e| format!("{}", e))
            .and_then(|p| {
                let path = p.to_str().unwrap().to_string();
                let event = Event::Inbound(InboundEvent::DownloadComplete(DownloadComplete {
                    update_id: id,
                    update_image: path,
                    signature: "signature".to_string()
                }));
                self.tx.send(event).map(|_| "ok".to_string()).map_err(|_| "send error".to_string())
            })
    }

    fn send_update_report(&mut self, m: UpdateReport) -> Result<String, String> {
        send_install_report(&self.config, &mut self.client, &m)
            .map(|_| "ok".to_string())
            .map_err(|e| format!("{}", e))
    }
}
