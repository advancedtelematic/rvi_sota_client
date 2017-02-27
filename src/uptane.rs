use cjson;
use std::collections::HashMap;

use datatype::{AccessToken, Error, Metadata, Role, Root, Snapshot, Targets, Timestamp,
               UpdateReport, UptaneConfig, UptaneCustom, UptaneMeta, Url, Verifier};
use http::{Client, Response};
use package_manager::PackageManager;


/// Last known version of each metadata file.
pub struct Version {
    root:      u64,
    targets:   u64,
    snapshot:  u64,
    timestamp: u64
}

impl Version {
    fn new() -> Self {
        Version {
            root:      0,
            targets:   0,
            snapshot:  0,
            timestamp: 0
        }
    }
}


/// Software over the air updates using Uptane endpoints.
pub struct Uptane {
    uptane_cfg:  UptaneConfig,
    device_uuid: String,
    version:     Version,
    verifier:    Verifier,
}

impl Uptane {
    pub fn new(cfg: UptaneConfig, device_uuid: String) -> Self {
        Uptane {
            uptane_cfg:  cfg,
            device_uuid: device_uuid,
            version:     Version::new(),
            verifier:    Verifier::new(),
        }
    }

    /// If using the director endpoint it returns:
    /// `<director_server>/<endpoint>`,
    /// Otherwise it returns the images server with device uuid:
    /// `<images_server>/<uuid>/<endpoint>`
    fn endpoint(&self, director: bool, endpoint: &str) -> Url {
        if director {
            let ref server = self.uptane_cfg.director_server;
            server.join(&format!("/{}", endpoint))
        } else {
            let ref server = self.uptane_cfg.images_server;
            server.join(&format!("/{}/{}", self.device_uuid, endpoint))
        }
    }


    /// GET the bytes response from the given endpoint.
    fn get_endpoint(&mut self, client: &Client, director: bool, endpoint: &str) -> Result<Vec<u8>, Error> {
        let resp_rx = client.get(self.endpoint(director, endpoint), None);
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't get bytes from endpoint".to_string())));
        match resp {
            Response::Success(data) => Ok(data.body),
            Response::Failed(data)  => Err(Error::from(data)),
            Response::Error(err)    => Err(err)
        }
    }

    /// PUT bytes to endpoint.
    fn put_endpoint(&mut self, client: &Client, director: bool, endpoint: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let resp_rx = client.put(self.endpoint(director, endpoint), Some(bytes));
        let resp    = try!(resp_rx.recv().ok_or(Error::Client("couldn't put bytes to endpoint".to_string())));
        match resp {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }


    /// Post a new manifest file.
    pub fn put_manifest(&mut self, client: &Client, director: bool, manifest: Vec<u8>) -> Result<(), Error> {
        debug!("put_manifest");
        self.put_endpoint(client, director, "manifest", manifest)
    }

    /// Get the root.json metadata.
    pub fn get_root(&mut self, client: &Client, director: bool, verifier: bool) -> Result<Root, Error> {
        debug!("get_root");
        let buf  = self.get_endpoint(client, director, "root.json")?;
        let meta = cjson::from_slice::<Metadata>(&buf)?;
        let root = cjson::from_slice::<Root>(&meta.signed)?;
        let out  = root.clone();

        if verifier {
            for (_, key) in root.keys {
                self.verifier.add_key(key);
            }
            for (role, data) in root.roles {
                self.verifier.add_role(role, data);
            }
        }

        debug!("checking root keys");
        self.verifier.verify(Role::Root, meta, 0)?;
        self.version.root = root.version;
        Ok(out)
    }

    /// Get the targets.json metadata.
    pub fn get_targets(&mut self, client: &Client, director: bool) -> Result<(UptaneMeta, bool), Error> {
        debug!("get_targets");
        let buf  = self.get_endpoint(client, director, "targets.json")?;
        let meta = cjson::from_slice::<Metadata>(&buf)?;
        let ts   = cjson::from_slice::<Targets>(&meta.signed)?;

        debug!("checking targets keys");
        self.verifier.verify(Role::Targets, meta, 0)?;
        if ts.version > self.version.targets {
            debug!("targets version increased from {} to {}", self.version.targets, ts.version);
            self.version.targets = ts.version;
            Ok((ts.targets, true))
        } else {
            Ok((ts.targets, false))
        }
    }

    /// Get the snapshot.json metadata.
    pub fn get_snapshot(&mut self, client: &Client, director: bool) -> Result<(UptaneMeta, bool), Error> {
        debug!("get_snapshot");
        let buf  = self.get_endpoint(client, director, "snapshot.json")?;
        let meta = cjson::from_slice::<Metadata>(&buf)?;
        let ss   = cjson::from_slice::<Snapshot>(&meta.signed)?;

        debug!("checking snapshot keys");
        self.verifier.verify(Role::Snapshot, meta, 0)?;
        if ss.version > self.version.snapshot {
            debug!("snapshot version increased from {} to {}", self.version.snapshot, ss.version);
            self.version.snapshot = ss.version;
            Ok((ss.meta, true))
        } else {
            Ok((ss.meta, false))
        }
    }

    /// Get the timestamp.json metadata and return a tuple of metadata and a
    /// boolean indicating whether the timestamp was updated.
    pub fn get_timestamp(&mut self, client: &Client, director: bool) -> Result<(UptaneMeta, bool), Error> {
        debug!("get_timestamp");
        let buf  = self.get_endpoint(client, director, "timestamp.json")?;
        let meta = cjson::from_slice::<Metadata>(&buf)?;
        let ts   = cjson::from_slice::<Timestamp>(&meta.signed)?;

        debug!("checking timestamp keys");
        self.verifier.verify(Role::Timestamp, meta, 0)?;
        if ts.version > self.version.timestamp {
            debug!("timestamp version increased from {} to {}", self.version.timestamp, ts.version);
            self.version.timestamp = ts.version;
            Ok((ts.meta, true))
        } else {
            Ok((ts.meta, false))
        }
    }

    pub fn extract_custom(&self, targets: UptaneMeta) -> UptaneCustom {
        debug!("extract_custom");
        let mut out = HashMap::new();
        for (file, meta) in targets {
            out.insert(file, meta.custom);
        }
        out
    }

    pub fn install_custom(&mut self, token: Option<&AccessToken>, custom: UptaneCustom) -> Result<UpdateReport, UpdateReport> {
        debug!("install_custom");
        let (id, path) = self.custom_path(custom)?;
        match PackageManager::Uptane.install_package(&path, token) {
            Ok( (code, output)) => Ok(UpdateReport::single(id, code, output)),
            Err((code, output)) => Err(UpdateReport::single(id, code, output))
        }
    }

    pub fn custom_path(&self, custom: UptaneCustom) -> Result<(String, String), UpdateReport> {
        unimplemented!();
    }
}


#[cfg(test)]
mod tests {
    use cjson;
    use serde_json as sjson;
    use std::convert::TryFrom;
    use std::fmt::Write;

    use super::*;
    use http::TestClient;


    const TIMESTAMP_JSON: &'static str = r#"{
        "signatures": [
            {
                "keyid": "1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4",
                "method": "ed25519",
                "sig": "90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaedf4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02"
            }
        ],
        "signed": {
            "_type": "Timestamp",
            "expires": "2030-01-01T00:00:00Z",
            "meta": {
                "snapshot.json": {
                    "hashes": {
                        "sha256": "c14aeb4ac9f4a8fc0d83d12482b9197452f6adf3eb710e3b1e2b79e8d14cb681"
                    },
                    "length": 1007
                }
            },
            "version": 1
        }
    }"#;


    #[ignore] // FIXME
    #[test]
    fn test_get_timestamp() {
        let sval = sjson::from_str(TIMESTAMP_JSON).expect("couldn't encode timestamp.json");
        let cval = cjson::Value::try_from(sval).expect("couldn't canonicalise timestamp.json");
        let cstr = cjson::to_string(&cval).expect("couldn't serialise timestamp.json");

        let mut hex = String::new();
        for &byte in cstr.as_bytes() {
            write!(&mut hex, "{:x} ", byte).unwrap();
        }
        debug!("cstr: {}", hex);

        let mut uptane = Uptane::new(UptaneConfig::default(), "test-uuid".to_string());
        let client     = TestClient::from(vec![cstr]);

        match uptane.get_timestamp(&client, true) {
            Ok((ts, ts_new)) => {
                assert_eq!(ts_new, true);
                let meta = ts.get("snapshot.json").expect("no snapshot.json metadata");
                assert_eq!(meta.length, 1007);
            }

            Err(err) => panic!("couldn't get_timestamp: {}", err)
        }
    }
}
