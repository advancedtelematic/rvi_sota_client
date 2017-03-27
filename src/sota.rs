use serde_json as json;
use std::{fs, io};
use std::fs::File;
use std::path::PathBuf;
use uuid::Uuid;

use datatype::{Config, DownloadComplete, Error, Package, UpdateReport, UpdateRequest, Url};
use http::{Client, Response};
use package_manager::Credentials;


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

    /// When using cert authentication returns an endpoint of: `<server>/core/<path>`
    /// otherwise returns an endpoint of: `<server>/api/v1/mydevice/<device-id>/<path>`.
    fn endpoint(&self, path: &str) -> Url {
        if self.config.tls.is_some() {
            self.config.tls.as_ref().unwrap().server.join(&format!("/core/{}", path))
        } else {
            self.config.core.server.join(&format!("/api/v1/mydevice/{}/{}", self.config.device.uuid, path))
        }
    }

    /// Returns the path to a package on the device.
    fn package_path(&self, id: &Uuid) -> Result<String, Error> {
        let mut path = PathBuf::new();
        path.push(&self.config.device.packages_dir);
        path.push(format!("{}", id));
        Ok(path.to_str().ok_or(Error::Parse(format!("Path is not valid UTF-8: {:?}", path)))?.to_string())
    }

    /// Query the Core server for any pending or in-flight package updates.
    pub fn get_update_requests(&mut self) -> Result<Vec<UpdateRequest>, Error> {
        let rx = self.client.get(self.endpoint("updates"), None);
        match rx.recv().expect("couldn't get update requests") {
            Response::Success(data) => Ok(json::from_slice::<Vec<UpdateRequest>>(&data.body)?),
            Response::Failed(data)  => Err(Error::from(data)),
            Response::Error(err)    => Err(err)
        }
    }

    /// Download a specific update from the Core server.
    pub fn download_update(&mut self, id: Uuid) -> Result<DownloadComplete, Error> {
        let rx   = self.client.get(self.endpoint(&format!("updates/{}/download", id)), None);
        let data = match rx.recv().expect("couldn't download update") {
            Response::Success(data) => data,
            Response::Failed(data)  => return Err(Error::from(data)),
            Response::Error(err)    => return Err(err)
        };

        let path = self.package_path(&id)?;
        let mut file = File::create(&path)
            .map_err(|err| Error::Client(format!("couldn't create path {}: {}", path, err)))?;
        let _ = io::copy(&mut &*data.body, &mut file)?;

        Ok(DownloadComplete {
            update_id:    id,
            update_image: path.to_string(),
            signature:    "".to_string()
        })
    }

    /// Install an update using the package manager.
    pub fn install_update<'t>(&mut self, id: Uuid, creds: &Credentials) -> Result<UpdateReport, UpdateReport> {
        let path = self.package_path(&id).expect("install_update expects a valid path");
        match self.config.device.package_manager.install_package(&path, creds) {
            Ok((code, output)) => {
                let _ = fs::remove_file(&path).unwrap_or_else(|err| error!("couldn't remove installed package: {}", err));
                Ok(UpdateReport::single(format!("{}", id), code, output))
            }

            Err((code, output)) => Err(UpdateReport::single(format!("{}", id), code, output))
        }
    }

    /// Send a list of the currently installed packages to the Core server.
    pub fn send_installed_packages(&mut self, packages: &Vec<Package>) -> Result<(), Error> {
        let rx = self.client.put(self.endpoint("installed"), Some(json::to_vec(packages)?));
        match rx.recv().expect("couldn't send installed packages") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }

    /// Send the outcome of a package update to the Core server.
    pub fn send_update_report(&mut self, report: &UpdateReport) -> Result<(), Error> {
        let url = self.endpoint(&format!("updates/{}", report.update_id));
        let rx  = self.client.post(url, Some(json::to_vec(&report.operation_results)?));
        match rx.recv().expect("couldn't send update report") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }

    /// Send system information from the device to the Core server.
    pub fn send_system_info(&mut self, body: Vec<u8>) -> Result<(), Error> {
        let rx = self.client.put(self.endpoint("system_info"), Some(body));
        match rx.recv().expect("couldn't send system info") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json as json;

    use datatype::{Config, Package, UpdateRequest, UpdateRequestStatus};
    use http::TestClient;


    #[test]
    fn test_get_update_requests() {
        let pending_update = UpdateRequest {
            requestId: Uuid::default(),
            status: UpdateRequestStatus::Pending,
            packageId: Package {
                name: "fake-pkg".to_string(),
                version: "0.1.1".to_string()
            },
            installPos: 0,
            createdAt: "2010-01-01".to_string()
        };

        let json = format!("[{}]", json::to_string(&pending_update).unwrap());
        let mut sota = Sota {
            config: &Config::default(),
            client: &mut TestClient::from(vec![json.to_string()]),
        };

        let updates: Vec<UpdateRequest> = sota.get_update_requests().unwrap();
        let ids: Vec<Uuid> = updates.iter().map(|p| p.requestId).collect();
        assert_eq!(ids, vec![Uuid::default()])
    }
}
