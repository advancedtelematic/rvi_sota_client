use serde_json as json;
use std::fs::{self, File};
use std::io;
use uuid::Uuid;

use datatype::{Config, DownloadComplete, Error, Package, InstallReport, InstallResult,
               UpdateRequest, Url};
use http::{Client, Response};
use pacman::Credentials;


/// Encapsulate the client configuration and HTTP client used for
/// software-over-the-air updates.
pub struct Sota<'c, 'h> {
    config: &'c Config,
    client: &'h Client,
}

impl<'c, 'h> Sota<'c, 'h> {
    /// Creates a new instance for Sota communication.
    pub fn new(config: &'c Config, client: &'h Client) -> Sota<'c, 'h> {
        Sota { config: config, client: client }
    }

    /// When using cert authentication returns an endpoint of: `<tls-server>/core/<path>`
    /// otherwise returns an endpoint of: `<core-server>/api/v1/mydevice/<device-id>/<path>`.
    fn endpoint(&self, path: &str) -> Url {
        if let Some(ref tls) = self.config.tls {
            tls.server.join(&format!("/core/{}", path))
        } else {
            self.config.core.server.join(&format!("/api/v1/mydevice/{}/{}", self.config.device.uuid, path))
        }
    }

    /// Check for any new package updates.
    pub fn get_update_requests(&mut self) -> Result<Vec<UpdateRequest>, Error> {
        let rx = self.client.get(self.endpoint("updates"), None);
        match rx.recv().expect("couldn't get update requests") {
            Response::Success(data) => Ok(json::from_slice::<Vec<UpdateRequest>>(&data.body)?),
            Response::Failed(data)  => Err(data.into()),
            Response::Error(err)    => Err(err)
        }
    }

    /// Download a specific update.
    pub fn download_update(&mut self, id: Uuid) -> Result<DownloadComplete, Error> {
        let rx = self.client.get(self.endpoint(&format!("updates/{}/download", id)), None);
        let data = match rx.recv().expect("couldn't download update") {
            Response::Success(data) => Ok(data),
            Response::Failed(data)  => Err(data.into()),
            Response::Error(err)    => Err(err)
        }?;

        let path = format!("{}/{}", self.config.device.packages_dir, id);
        let mut file = File::create(&path).map_err(|err| Error::Client(format!("couldn't create path {}: {}", path, err)))?;
        let _ = io::copy(&mut &*data.body, &mut file)?;
        Ok(DownloadComplete { update_id: id, update_image: path.into(), signature: "".into() })
    }

    /// Install an update using the current package manager.
    pub fn install_update(&mut self, id: &Uuid, creds: &Credentials) -> Result<InstallResult, Error> {
        let path = format!("{}/{}", self.config.device.packages_dir, id);
        self.config.device
            .package_manager
            .install_package(&path, creds)
            .and_then(|outcome| {
                fs::remove_file(&path).unwrap_or_else(|err| error!("couldn't remove installed package: {}", err));
                Ok(outcome.into_result(format!("{}", id)))
            })
    }

    /// Send a list of the currently installed packages.
    pub fn send_installed_packages(&mut self, packages: &[Package]) -> Result<(), Error> {
        let rx = self.client.put(self.endpoint("installed"), Some(json::to_vec(packages)?));
        match rx.recv().expect("couldn't send installed packages") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(data.into()),
            Response::Error(err)   => Err(err)
        }
    }

    /// Send the outcome of a package installation.
    pub fn send_install_report(&mut self, report: &InstallReport) -> Result<(), Error> {
        let url = self.endpoint(&format!("updates/{}", report.update_id));
        let rx  = self.client.post(url, Some(json::to_vec(&report.operation_results)?));
        match rx.recv().expect("couldn't send update report") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(data.into()),
            Response::Error(err)   => Err(err)
        }
    }

    /// Send system information from the device.
    pub fn send_system_info(&mut self, body: Vec<u8>) -> Result<(), Error> {
        let rx = self.client.put(self.endpoint("system_info"), Some(body));
        match rx.recv().expect("couldn't send system info") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(data.into()),
            Response::Error(err)   => Err(err)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json as json;

    use datatype::{Config, Package, UpdateRequest, RequestStatus};
    use http::TestClient;


    #[test]
    fn test_get_update_requests() {
        let pend = UpdateRequest {
            requestId: Uuid::default(),
            status: RequestStatus::Pending,
            packageId: Package {
                name: "fake-pkg".to_string(),
                version: "0.1.1".to_string()
            },
            installPos: 0,
            createdAt: "2010-01-01".to_string()
        };

        let mut sota = Sota {
            config: &Config::default(),
            client: &mut TestClient::from(vec![format!("[{}]", json::to_string(&pend).unwrap()).into_bytes()]),
        };
        let updates: Vec<UpdateRequest> = sota.get_update_requests().unwrap();
        let ids: Vec<Uuid> = updates.iter().map(|p| p.requestId).collect();
        assert_eq!(ids, vec![Uuid::default()])
    }
}
