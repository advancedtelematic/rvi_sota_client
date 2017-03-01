use serde_json as json;
use std::collections::HashMap;

use datatype::{AccessToken, Error, Metadata, Role, Root, SignedMeta, SignedCustom,
               Snapshot, Targets, Timestamp, UpdateReport, UptaneConfig, Url, Verifier};
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
        Version { root: 0, targets: 0, snapshot: 0, timestamp: 0 }
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
        let rx = client.get(self.endpoint(director, endpoint), None);
        match rx.recv().ok_or(Error::Client("couldn't get bytes from endpoint".to_string()))? {
            Response::Success(data) => Ok(data.body),
            Response::Failed(data)  => Err(Error::from(data)),
            Response::Error(err)    => Err(err)
        }
    }

    /// PUT bytes to endpoint.
    fn put_endpoint(&mut self, client: &Client, director: bool, endpoint: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let rx = client.put(self.endpoint(director, endpoint), Some(bytes));
        match rx.recv().ok_or(Error::Client("couldn't put bytes to endpoint".to_string()))? {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(Error::from(data)),
            Response::Error(err)   => Err(err)
        }
    }


    /// Put a new manifest file to the Director server.
    pub fn put_manifest(&mut self, client: &Client, manifest: Vec<u8>) -> Result<(), Error> {
        debug!("put_manifest");
        self.put_endpoint(client, true, "manifest", manifest)
    }

    /// Add the root.json metadata to the verifier and return a new version indicator.
    pub fn get_root(&mut self, client: &Client, director: bool) -> Result<bool, Error> {
        debug!("get_root");
        let buf  = self.get_endpoint(client, director, "root.json")?;
        let meta = json::from_slice::<Metadata>(&buf)?;
        let root = json::from_value::<Root>(meta.signed.clone())?;

        for (id, key) in root.keys {
            trace!("adding key: {:?}", key);
            self.verifier.add_key(id, key);
        }
        for (role, data) in root.roles {
            trace!("adding roledata: {:?}", data);
            self.verifier.add_role(role, data);
        }

        debug!("checking root keys");
        self.verifier.verify(&Role::Root, &meta, 0)?;
        if root.version > self.version.root {
            debug!("root version increased from {} to {}", self.version.root, root.version);
            self.version.root = root.version;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the targets.json metadata and a new version indicator.
    pub fn get_targets(&mut self, client: &Client, director: bool) -> Result<(Targets, bool), Error> {
        debug!("get_targets");
        let buf  = self.get_endpoint(client, director, "targets.json")?;
        let meta = json::from_slice::<Metadata>(&buf)?;
        let targ = json::from_value::<Targets>(meta.signed.clone())?;

        debug!("checking targets keys");
        self.verifier.verify(&Role::Targets, &meta, 0)?;
        if targ.version > self.version.targets {
            debug!("targets version increased from {} to {}", self.version.targets, targ.version);
            self.version.targets = targ.version;
            Ok((targ, true))
        } else {
            Ok((targ, false))
        }
    }

    /// Get the snapshot.json metadata and a new version indicator.
    pub fn get_snapshot(&mut self, client: &Client, director: bool) -> Result<(Snapshot, bool), Error> {
        debug!("get_snapshot");
        let buf  = self.get_endpoint(client, director, "snapshot.json")?;
        let meta = json::from_slice::<Metadata>(&buf)?;
        let snap = json::from_value::<Snapshot>(meta.signed.clone())?;

        debug!("checking snapshot keys");
        self.verifier.verify(&Role::Snapshot, &meta, 0)?;
        if snap.version > self.version.snapshot {
            debug!("snapshot version increased from {} to {}", self.version.snapshot, snap.version);
            self.version.snapshot = snap.version;
            Ok((snap, true))
        } else {
            Ok((snap, false))
        }
    }

    /// Get the timestamp.json metadata and a new version indicator.
    pub fn get_timestamp(&mut self, client: &Client, director: bool) -> Result<(Timestamp, bool), Error> {
        debug!("get_timestamp");
        let buf  = self.get_endpoint(client, director, "timestamp.json")?;
        let meta = json::from_slice::<Metadata>(&buf)?;
        let time = json::from_value::<Timestamp>(meta.signed.clone())?;

        debug!("checking timestamp keys");
        self.verifier.verify(&Role::Timestamp, &meta, 0)?;
        if time.version > self.version.timestamp {
            debug!("timestamp version increased from {} to {}", self.version.timestamp, time.version);
            self.version.timestamp = time.version;
            Ok((time, true))
        } else {
            Ok((time, false))
        }
    }


    pub fn extract_custom(&self, targets: HashMap<String, SignedMeta>) -> HashMap<String, SignedCustom> {
        debug!("extract_custom");
        let mut out = HashMap::new();
        for (file, meta) in targets {
            if let Some(custom) = meta.custom {
                out.insert(file, custom);
            }
        }
        out
    }

    pub fn install_custom(&mut self,
                          token:  Option<&AccessToken>,
                          custom: HashMap<String, SignedCustom>) -> Result<UpdateReport, UpdateReport> {
        debug!("install_custom");
        let (id, path) = self.custom_path(custom)?;
        match PackageManager::Uptane.install_package(&path, token) {
            Ok( (code, output)) => Ok(UpdateReport::single(id, code, output)),
            Err((code, output)) => Err(UpdateReport::single(id, code, output))
        }
    }

    pub fn custom_path(&self, custom: HashMap<String, SignedCustom>) -> Result<(String, String), UpdateReport> {
        unimplemented!();
    }
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use super::*;
    use datatype::{Metadata, SignedManifest, SignedVersion};
    use http::TestClient;


    fn read_file(path: &str) -> Vec<u8> {
        let mut file = File::open(path).unwrap_or_else(|err| panic!("couldn't open path: {}\n{}", path, err));
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap_or_else(|err| panic!("couldn't read path: {}\n{}", path, err));
        buf
    }

    fn client_from_paths(paths: &[&str]) -> TestClient<Vec<u8>> {
        let mut replies = Vec::new();
        for path in paths {
            replies.push(read_file(path));
        }
        TestClient::from(replies)
    }

    #[test]
    fn test_read_manifest() {
        let bytes = read_file("tests/uptane/ats/manifest.json");
        let meta = json::from_slice::<Metadata>(&bytes).expect("couldn't load manifest");
        let signed = json::from_value::<SignedManifest>(meta.signed).expect("couldn't load signed manifest");
        assert_eq!(signed.primary_ecu_serial, "{ecu serial}");

        let mut metas = json::from_value::<Vec<Metadata>>(signed.ecu_version_manifest).expect("couldn't load ecu_version_manifest");
        assert_eq!(metas.len(), 1);
        let meta1 = metas.pop().unwrap();
        let version = json::from_value::<SignedVersion>(meta1.signed).expect("couldn't load first manifest");
        assert_eq!(version.installed_image.filepath, "/{ostree-refname}");
    }

    #[test]
    fn test_get_targets_director() {
        let mut uptane = Uptane::new(UptaneConfig::default(), "test-get-targets-director".to_string());
        let client = client_from_paths(&[
            "tests/uptane/ed25519/root.json",
            "tests/uptane/ats/targets_director.json",
        ]);

        assert_eq!(true, uptane.get_root(&client, true).expect("couldn't get_root"));
        match uptane.get_targets(&client, true) {
            Ok((ts, ts_new)) => {
                assert_eq!(ts_new, true);
                {
                    let meta = ts.targets.get("/{ostree-refname}").expect("no /{ostree-refname} metadata");
                    assert_eq!(meta.length, 31);
                    let hash = meta.hashes.get("sha256").expect("couldn't get sha256 hash");
                    assert_eq!(hash, "65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da");
                }
                let custom = uptane.extract_custom(ts.targets);
                let image = custom.get("/{ostree-refname}").expect("couldn't get /{ostree-refname} custom");
                assert_eq!(image.ecuIdentifier, "identifier-file1");
            }

            Err(err) => panic!("couldn't get_targets_director: {}", err)
        }
    }

    #[test]
    fn test_get_snapshot() {
        let mut uptane = Uptane::new(UptaneConfig::default(), "test-get-snapshot".to_string());
        let client = client_from_paths(&[
            "tests/uptane/ed25519/root.json",
            "tests/uptane/ed25519/snapshot.json",
        ]);

        assert_eq!(true, uptane.get_root(&client, true).expect("couldn't get_root"));
        match uptane.get_snapshot(&client, true) {
            Ok((ss, ss_new)) => {
                assert_eq!(ss_new, true);
                let meta = ss.meta.get("targets.json.gz").expect("no targets.json.gz metadata");
                assert_eq!(meta.length, 599);
                let hash = meta.hashes.get("sha256").expect("couldn't get sha256 hash");
                assert_eq!(hash, "9f8aff5b55ee4b3140360d99b39fa755a3ea640462072b4fd74bdd72e6fe245a");
            }

            Err(err) => panic!("couldn't get_snapshot: {}", err)
        }
    }

    #[test]
    fn test_get_timestamp() {
        let mut uptane = Uptane::new(UptaneConfig::default(), "test-get-timestamp".to_string());
        let client = client_from_paths(&[
            "tests/uptane/ed25519/root.json",
            "tests/uptane/ed25519/timestamp.json",
        ]);

        assert_eq!(true, uptane.get_root(&client, true).expect("get_root failed"));
        match uptane.get_timestamp(&client, true) {
            Ok((ts, ts_new)) => {
                assert_eq!(ts_new, true);
                let meta = ts.meta.get("snapshot.json").expect("no snapshot.json metadata");
                assert_eq!(meta.length, 1007);
            }

            Err(err) => panic!("couldn't get_timestamp: {}", err)
        }
    }
}
