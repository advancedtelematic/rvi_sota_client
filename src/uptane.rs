use serde_json as json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use datatype::{Config, EcuManifests, Error, Ostree, Role, Root, Snapshot, Targets,
               Timestamp, TufCustom, TufMeta, TufSigned, Url, Verifier};
use http::{Client, Response};
use datatype::{SigType, PrivateKey};


/// Last known version of each metadata file.
pub struct Version {
    root:      u64,
    targets:   u64,
    snapshot:  u64,
    timestamp: u64
}

impl Default for Version {
    fn default() -> Self {
        Version { root: 0, targets: 0, snapshot: 0, timestamp: 0 }
    }
}


/// Software over the air updates using Uptane endpoints.
pub struct Uptane {
    gateway:  Url,
    deviceid: String,
    version:  Version,
    verifier: Verifier,
    serial:   String,
    privkey:  PrivateKey,
}

impl Uptane {
    pub fn new(config: &Config) -> Self {
        let tls_cfg = config.tls.as_ref().expect("uptane mode expects [tls] config");
        let der_key = read_file(&config.uptane.private_key_path)
            .unwrap_or_else(|err| panic!("couldn't read uptane.private_key_path: {}", err));

        Uptane {
            gateway:  tls_cfg.server.clone(),
            deviceid: config.device.uuid.clone(),
            version:  Version::default(),
            verifier: Verifier::new(),
            serial:   config.uptane.primary_ecu_serial.clone(),
            privkey:  PrivateKey {
                // FIXME: keyid
                keyid:   "e453c713367595e1a9e5c1de8b2c039fe4178094bdaf2d52b1993fdd1a76ee26".into(),
                der_key: der_key
            },
        }
    }

    /// If using the director endpoint it returns:
    /// `<gateway-server>/director/<endpoint>`,
    /// Otherwise it returns the images server with device uuid:
    /// `<gateway-server>/repo/<uuid>/<endpoint>`
    fn endpoint(&self, director: bool, endpoint: &str) -> Url {
        if director {
            self.gateway.join(&format!("/director/{}", endpoint))
        } else {
            self.gateway.join(&format!("/repo/{}/{}", self.deviceid, endpoint))
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
    pub fn put_manifest(&mut self, client: &Client) -> Result<(), Error> {
        debug!("put_manifest");
        let branch   = Ostree::get_current_branch()?;
        let ecu_ver  = branch.ecu_version(self.serial.clone());
        let ecu_sign = TufSigned::sign(json::to_value(ecu_ver)?, &self.privkey, SigType::RsaSsaPss)?;

        let manifests = EcuManifests {
            primary_ecu_serial:   self.serial.clone(),
            ecu_version_manifest: vec![ecu_sign],
        };
        let signed = TufSigned::sign(json::to_value(manifests)?, &self.privkey, SigType::RsaSsaPss)?;
        self.put_endpoint(client, true, "manifest", json::to_vec(&signed)?)
    }

    /// Add the root.json metadata to the verifier and return a new version indicator.
    pub fn get_root(&mut self, client: &Client, director: bool) -> Result<bool, Error> {
        debug!("get_root");
        let buf  = self.get_endpoint(client, director, "root.json")?;
        let meta = json::from_slice::<TufSigned>(&buf)?;
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
        if self.verifier.verify(&Role::Root, &meta)? > self.version.root {
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
        let meta = json::from_slice::<TufSigned>(&buf)?;
        let targ = json::from_value::<Targets>(meta.signed.clone())?;

        debug!("checking targets keys");
        if self.verifier.verify(&Role::Targets, &meta)? > self.version.targets {
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
        let meta = json::from_slice::<TufSigned>(&buf)?;
        let snap = json::from_value::<Snapshot>(meta.signed.clone())?;

        debug!("checking snapshot keys");
        if self.verifier.verify(&Role::Snapshot, &meta)? > self.version.snapshot {
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
        let meta = json::from_slice::<TufSigned>(&buf)?;
        let time = json::from_value::<Timestamp>(meta.signed.clone())?;

        debug!("checking timestamp keys");
        if self.verifier.verify(&Role::Timestamp, &meta)? > self.version.timestamp {
            debug!("timestamp version increased from {} to {}", self.version.timestamp, time.version);
            self.version.timestamp = time.version;
            Ok((time, true))
        } else {
            Ok((time, false))
        }
    }

    pub fn extract_custom(&self, targets: HashMap<String, TufMeta>) -> HashMap<String, TufCustom> {
        debug!("extract_custom");
        let mut out = HashMap::new();
        for (file, meta) in targets {
            let _ = meta.custom.map(|c| out.insert(file, c));
        }
        out
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, Error> {
    let mut file = File::open(path).map_err(|err| Error::Client(format!("couldn't open path: {}\n{}", path, err)))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|err| Error::Client(format!("couldn't read path: {}\n{}", path, err)))?;
    Ok(buf)
}


#[cfg(test)]
mod tests {
    use super::*;
    use pem;

    use datatype::{EcuManifests, EcuVersion, TufSigned};
    use http::TestClient;


    const RSA_2048_PRIV: &'static str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdC9QttkMbF5qB\n2plVU2hhG2sieXS2CVc3E8rm/oYGc9EHnlPMcAuaBtn9jaBo37PVYO+VFInzMu9f\nVMLm7d/hQxv4PjTBpkXvw1Ad0Tqhg/R8Lc4SXPxWxlVhg0ahLn3kDFQeEkrTNW7k\nxpAxWiE8V09ETcPwyNhPfcWeiBePwh8ySJ10IzqHt2kXwVbmL4F/mMX07KBYWIcA\n52TQLs2VhZLIaUBv9ZBxymAvogGz28clx7tHOJ8LZ/daiMzmtv5UbXPdt+q55rLJ\nZ1TuG0CuRqhTOllXnIvAYRQr6WBaLkGGbezQO86MDHBsV5TsG6JHPorrr6ogo+Lf\npuH6dcnHAgMBAAECggEBAMC/fs45fzyRkXYn4srHh14d5YbTN9VAQd/SD3zrdn0L\n4rrs8Y90KHmv/cgeBkFMx+iJtYBev4fk41xScf2icTVhKnOF8sTls1hGDIdjmeeb\nQ8ZAvs++a39TRMJaEW2dN8NyiKsMMlkH3+H3z2ZpfE+8pm8eDHza9dwjBP6fF0SP\nV1XPd2OSrJlvrgBrAU/8WWXYSYK+5F28QtJKsTuiwQylIHyJkd8cgZhgYXlUVvTj\nnHFJblpAT0qphji7p8G4Ejg+LNxu/ZD+D3wQ6iIPgKFVdC4uXmPwlf1LeYqXW0+g\ngTmHY7a/y66yn1H4A5gyfx2EffFMQu0Sl1RqzDVYYjECgYEA9Hy2QsP3pxW27yLs\nCu5e8pp3vZpdkNA71+7v2BVvaoaATnsSBOzo3elgRYsN0On4ObtfQXB3eC9poNuK\nzWxj8bkPbVOCpSpq//sUSqkh/XCmAhDl78BkgmWDb4EFEgcAT2xPBTHkb70jVAXB\nE1HBwsBcXhdxzRt8IYiBG+68d/8CgYEA53SJYpJ809lfpAG0CU986FFD7Fi/SvcX\n21TVMn1LpHuH7MZ2QuehS0SWevvspkIUm5uT3PrhTxdohAInNEzsdeHhTU11utIO\nrKnrtgZXKsBG4idsHu5ZQzp4n3CBEpfPFbOtP/UEKI/IGaJWGXVgG4J6LWmQ9LK9\nilNTaOUQ7jkCgYB+YP0B9DTPLN1cLgwf9mokNA7TdrkJA2r7yuo2I5ZtVUt7xghh\nfWk+VMXMDP4+UMNcbGvn8s/+01thqDrOx0m+iO/djn6JDC01Vz98/IKydImLpdqG\nHUiXUwwnFmVdlTrm01DhmZHA5N8fLr5IU0m6dx8IEExmPt/ioaJDoxvPVwKBgC+8\n1H01M3PKWLSN+WEWOO/9muHLaCEBF7WQKKzSNODG7cEDKe8gsR7CFbtl7GhaJr/1\ndajVQdU7Qb5AZ2+dEgQ6Q2rbOBYBLy+jmE8hvaa+o6APe3hhtp1sGObhoG2CTB7w\nwSH42hO3nBDVb6auk9T4s1Rcep5No1Q9XW28GSLZAoGATFlXg1hqNKLO8xXq1Uzi\nkDrN6Ep/wq80hLltYPu3AXQn714DVwNa3qLP04dAYXbs9IaQotAYVVGf6N1IepLM\nfQU6Q9fp9FtQJdU+Mjj2WMJVWbL0ihcU8VZV5TviNvtvR1rkToxSLia7eh39AY5G\nvkgeMZm7SwqZ9c/ZFnjJDqc=\n-----END PRIVATE KEY-----";

    fn new_uptane(primary_ecu_serial: String) -> Uptane {
        Uptane {
            gateway:  "http://localhost:8000".parse().unwrap(),
            deviceid: primary_ecu_serial.clone(),
            version:  Version::default(),
            verifier: Verifier::new(),
            serial:   primary_ecu_serial,
            privkey:  PrivateKey {
                keyid:   "e453c713367595e1a9e5c1de8b2c039fe4178094bdaf2d52b1993fdd1a76ee26".into(),
                der_key: pem::parse(RSA_2048_PRIV).unwrap().contents
            },
        }
    }

    fn client_from_paths(paths: &[&str]) -> TestClient<Vec<u8>> {
        let mut replies = Vec::new();
        for path in paths {
            replies.push(read_file(path).unwrap_or_else(|err| panic!("{}", err)));
        }
        TestClient::from(replies)
    }

    #[test]
    fn test_read_manifest() {
        let bytes = read_file("tests/uptane/ats/manifest.json").unwrap_or_else(|err| panic!("{}", err));
        let signed = json::from_slice::<TufSigned>(&bytes).expect("couldn't load manifest");
        let mut ecus = json::from_value::<EcuManifests>(signed.signed).expect("couldn't load signed manifest");
        assert_eq!(ecus.primary_ecu_serial, "{ecu serial}");
        assert_eq!(ecus.ecu_version_manifest.len(), 1);
        let ver0 = ecus.ecu_version_manifest.pop().unwrap();
        let ecu0 = json::from_value::<EcuVersion>(ver0.signed).expect("couldn't load first manifest");
        assert_eq!(ecu0.installed_image.filepath, "/{ostree-refname}");
    }

    #[test]
    fn test_get_targets_director() {
        let mut uptane = new_uptane("test-get-targets-director".into());
        let client = client_from_paths(&[
            "tests/uptane/repo_1/root.json",
            "tests/uptane/repo_1/targets.json",
        ]);

        assert!(uptane.get_root(&client, true).expect("couldn't get_root"));
        match uptane.get_targets(&client, true) {
            Ok((ts, ts_new)) => {
                assert_eq!(ts_new, true);
                {
                    let meta = ts.targets.get("/file.img").expect("no /file.img metadata");
                    assert_eq!(meta.length, 1337);
                    let hash = meta.hashes.get("sha256").expect("couldn't get sha256 hash");
                    assert_eq!(hash, "dd250ea90b872a4a9f439027ac49d853c753426f71f61ae44c2f360a16179fb9");
                }
                let custom = uptane.extract_custom(ts.targets);
                let image = custom.get("/file.img").expect("couldn't get /file.img custom");
                assert_eq!(image.ecuIdentifier, "some-ecu-id");
            }

            Err(err) => panic!("couldn't get_targets_director: {}", err)
        }
    }

    #[test]
    fn test_get_snapshot() {
        let mut uptane = new_uptane("test-get-snapshot".into());
        let client = client_from_paths(&[
            "tests/uptane/repo_1/root.json",
            "tests/uptane/repo_1/snapshot.json",
        ]);

        assert!(uptane.get_root(&client, true).expect("couldn't get_root"));
        match uptane.get_snapshot(&client, true) {
            Ok((ss, ss_new)) => {
                assert_eq!(ss_new, true);
                let meta = ss.meta.get("targets.json").expect("no targets.json metadata");
                assert_eq!(meta.length, 653);
                let hash = meta.hashes.get("sha256").expect("couldn't get sha256 hash");
                assert_eq!(hash, "086b26f2ea32d51543533b2a150de619d08f45a151c1f59c07eaa8a18a4a9548");
            }

            Err(err) => panic!("couldn't get_snapshot: {}", err)
        }
    }

    extern crate env_logger;
    #[test]
    fn test_get_timestamp() {
        env_logger::init().expect("boo");
        let mut uptane = new_uptane("test-get-timestamp".into());
        let client = client_from_paths(&[
            "tests/uptane/repo_1/root.json",
            "tests/uptane/repo_1/timestamp.json",
        ]);

        assert!(uptane.get_root(&client, true).expect("get_root failed"));
        match uptane.get_timestamp(&client, true) {
            Ok((ts, ts_new)) => {
                assert_eq!(ts_new, true);
                let meta = ts.meta.get("snapshot.json").expect("no snapshot.json metadata");
                assert_eq!(meta.length, 696);
            }

            Err(err) => panic!("couldn't get_timestamp: {}", err)
        }
    }
}
