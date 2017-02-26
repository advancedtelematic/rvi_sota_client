use rustc_serialize::json;
use std::{fs, io};
use std::fs::File;
use std::path::PathBuf;

use datatype::{AccessToken, AuthConfig, Config, DownloadComplete, Error, Package, UpdateReport,
               UpdateRequest, UpdateRequestId, Url};
use http::{Client, Response};


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

    /// Takes a path and returns a new endpoint of the format
    /// `<server>/api/v1/mydevice/<device-id>/<path>`.
    fn endpoint(&self, path: &str) -> Url {
        match self.config.auth {
            Some(ref auth @ AuthConfig { p12_path: Some(_), .. }) =>
                // certificate mode, talking to device gateway
                auth.server.join(&format!("/core/{}", path)),
            _ => // talking to core by default
                self.config.core.server.join(&format!("/api/v1/mydevice/{}/{}", self.config.device.uuid, path))
        }
    }

    /// Returns the path to a package on the device.
    fn package_path(&self, id: UpdateRequestId) -> Result<String, Error> {
        let mut path = PathBuf::new();
        path.push(&self.config.device.packages_dir);
        path.push(id);
        Ok(try!(path.to_str().ok_or(Error::Parse(format!("Path is not valid UTF-8: {:?}", path)))).to_string())
    }

    /// Query the Core server for any pending or in-flight package updates.
    pub fn get_update_requests(&mut self) -> Result<Vec<UpdateRequest>, Error> {
        let resp_rx = self.client.get(self.endpoint("updates"), None);
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't get update requests".to_string())));
        let data    = match resp {
            Response::Success(data) => data,
            Response::Failed(data)  => return Err(Error::from(data)),
            Response::Error(err)    => return Err(err)
        };

        let text = try!(String::from_utf8(data.body));
        Ok(try!(json::decode::<Vec<UpdateRequest>>(&text)))
    }

    /// Download a specific update from the Core server.
    pub fn download_update(&mut self, id: UpdateRequestId) -> Result<DownloadComplete, Error> {
        let url     = self.endpoint(&format!("updates/{}/download", id));
        let resp_rx = self.client.get(url, None);
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't download update".to_string())));
        let data    = match resp {
            Response::Success(data) => data,
            Response::Failed(data)  => return Err(Error::from(data)),
            Response::Error(err)    => return Err(err)
        };

        let path     = try!(self.package_path(id.clone()));
        let mut file = try!(File::create(&path));
        let _        = io::copy(&mut &*data.body, &mut file);
        Ok(DownloadComplete {
            update_id:    id,
            update_image: path.to_string(),
            signature:    "".to_string()
        })
    }

    /// Install an update using the package manager.
    pub fn install_update<'t>(&mut self, token: Option<&AccessToken>, id: UpdateRequestId) -> Result<UpdateReport, UpdateReport> {
        let ref pacman = self.config.device.package_manager;
        let path       = self.package_path(id.clone()).expect("install_update expects a valid path");
        pacman.install_package(&path, token).and_then(|(code, output)| {
            let _ = fs::remove_file(&path).unwrap_or_else(|err| error!("couldn't remove installed package: {}", err));
            Ok(UpdateReport::single(id.clone(), code, output))
        }).or_else(|(code, output)| {
            Err(UpdateReport::single(id.clone(), code, output))
        })
    }

    /// Send a list of the currently installed packages to the Core server.
    pub fn send_installed_packages(&mut self, packages: &Vec<Package>) -> Result<(), Error> {
        let body    = try!(json::encode(packages));
        let resp_rx = self.client.put(self.endpoint("installed"), Some(body.into_bytes()));
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't send installed packages".to_string())));

        match resp {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }

    /// Send the outcome of a package update to the Core server.
    pub fn send_update_report(&mut self, update_report: &UpdateReport) -> Result<(), Error> {
        let body    = try!(json::encode(&update_report.operation_results));
        let url     = self.endpoint(&format!("updates/{}", update_report.update_id));
        let resp_rx = self.client.post(url, Some(body.into_bytes()));
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't send update report".to_string())));

        match resp {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }

    /// Send system information from the device to the Core server.
    pub fn send_system_info(&mut self, body: &str) -> Result<(), Error> {
        let resp_rx = self.client.put(self.endpoint("system_info"), Some(body.as_bytes().to_vec()));
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't send system info".to_string())));

        match resp {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }
}


#[cfg(test)]
mod tests {
    use rustc_serialize::json;

    use super::*;
    use datatype::{Config, Package, UpdateRequest, UpdateRequestStatus};
    use http::TestClient;


    #[test]
    fn test_get_update_requests() {
        let pending_update = UpdateRequest {
            requestId: "someid".to_string(),
            status: UpdateRequestStatus::Pending,
            packageId: Package {
                name: "fake-pkg".to_string(),
                version: "0.1.1".to_string()
            },
            installPos: 0,
            createdAt: "2010-01-01".to_string()
        };

        let json = format!("[{}]", json::encode(&pending_update).unwrap());
        let mut sota = Sota {
            config: &Config::default(),
            client: &mut TestClient::from(vec![json.to_string()]),
        };

        let updates: Vec<UpdateRequest> = sota.get_update_requests().unwrap();
        let ids: Vec<String> = updates.iter().map(|p| p.requestId.clone()).collect();
        assert_eq!(ids, vec!["someid".to_string()])
    }
}
