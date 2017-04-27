use base64;
use hex::FromHex;
use pem;
use ring::digest;
use serde_json as json;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::Path;

use datatype::{Config, EcuCustom, EcuManifests, Error, Key, KeyType, OstreePackage,
               PrivateKey, RoleData, RoleMeta, RoleName, Signature, SignatureType,
               TufMeta, TufRole, TufSigned, Url, canonicalize_json};
use http::{Client, Response};
use util::Util;


/// Uptane service to communicate with.
#[derive(Clone, Copy)]
pub enum Service {
    Director,
    Repo,
}

impl Display for Service {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Service::Director => write!(f, "director"),
            Service::Repo     => write!(f, "repo"),
        }
    }
}

/// Software-over-the-air updates using Uptane verification.
pub struct Uptane {
    pub director_server:  Url,
    pub repo_server:      Url,
    pub metadata_path:    String,
    pub persist_metadata: bool,

    pub primary_ecu: String,
    pub device_id:   String,
    pub private_key: PrivateKey,
    pub sig_type:    SignatureType,

    pub director_verifier: Verifier,
    pub repo_verifier:     Verifier,
}

impl Uptane {
    pub fn new(client: &Client, config: &Config) -> Result<Self, Error> {
        let cfg = &config.uptane;
        let der = Util::read_file(&config.uptane.private_key_path)
            .map_err(|err| Error::Client(format!("couldn't read uptane.private_key_path: {}", err)))?;

        let mut uptane = Uptane {
            director_server:  cfg.director_server.clone(),
            repo_server:      cfg.repo_server.clone(),
            metadata_path:    cfg.metadata_path.clone(),
            persist_metadata: true,

            primary_ecu: cfg.primary_ecu_serial.clone(),
            device_id:   format!("{}", config.device.uuid),
            private_key: PrivateKey {
                keyid: digest::digest(&digest::SHA256, &der)
                    .as_ref()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>(),
                der_key: der
            },
            sig_type: SignatureType::RsaSsaPss,

            director_verifier: Verifier::new(cfg.director_root_keys.clone()),
            repo_verifier:     Verifier::new(cfg.repo_root_keys.clone()),
        };

        let _ = uptane.get_root(client, Service::Director)?;
        Ok(uptane)
    }

    /// Returns a URL based on the uptane service.
    fn endpoint(&self, service: Service, endpoint: &str) -> Url {
        match service {
            Service::Director => self.director_server.join(&format!("/{}", endpoint)),
            Service::Repo     => self.repo_server.join(&format!("/{}/{}", self.device_id, endpoint))
        }
    }

    /// Returns the respective key verifier for an uptane service.
    fn verifier(&mut self, service: Service) -> &mut Verifier {
        match service {
            Service::Director => &mut self.director_verifier,
            Service::Repo     => &mut self.repo_verifier
        }
    }

    /// GET the bytes response from the given endpoint.
    fn get(&mut self, client: &Client, service: Service, endpoint: &str) -> Result<Vec<u8>, Error> {
        let rx = client.get(self.endpoint(service, endpoint), None);
        match rx.recv().expect("couldn't GET from uptane") {
            Response::Success(data) => Ok(data.body),
            Response::Failed(data)  => Err(data.into()),
            Response::Error(err)    => Err(err)
        }
    }

    /// PUT bytes to endpoint.
    fn put(&mut self, client: &Client, service: Service, endpoint: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let rx = client.put(self.endpoint(service, endpoint), Some(bytes));
        match rx.recv().expect("couldn't PUT bytes to uptane") {
            Response::Success(_)   => Ok(()),
            Response::Failed(data) => Err(data.into()),
            Response::Error(err)   => Err(err)
        }
    }

    /// Fetch the specified role's metadata from the Director service.
    pub fn get_director(&mut self, client: &Client, role: RoleName) -> Result<Verified, Error> {
        let json = self.get_json(client, Service::Director, role)?;
        self.verify_tuf(Service::Director, role, json::from_slice::<TufSigned>(&json)?)
    }

    /// Fetch the specified role's metadata from the Repo service.
    pub fn get_repo(&mut self, client: &Client, role: RoleName) -> Result<Verified, Error> {
        let json = self.get_json(client, Service::Repo, role)?;
        self.verify_tuf(Service::Repo, role, json::from_slice::<TufSigned>(&json)?)
    }

    /// Read local metadata if it exists or download it otherwise.
    fn get_json(&mut self, client: &Client, service: Service, role: RoleName) -> Result<Vec<u8>, Error> {
        let path = format!("{}/{}/{}.json", &self.metadata_path, service, &role);
        if Path::new(&path).exists() {
            debug!("reading {}.json from {}", role, path);
            Util::read_file(&path)
        } else {
            debug!("fetching {}.json from {}", role, service);
            self.get(client, service, &format!("{}.json", role))
        }
    }

    /// Fetch the root.json metadata, adding it's keys to the verifier.
    pub fn get_root(&mut self, client: &Client, service: Service) -> Result<Verified, Error> {
        let json = self.get_json(client, service, RoleName::Root)?;
        let signed = json::from_slice::<TufSigned>(&json)?;
        let data = json::from_value::<RoleData>(signed.signed.clone())?;

        for (role, meta) in data.roles.ok_or(Error::UptaneMissingRoles)? {
            self.verifier(service).add_meta(role, meta)?;
        }
        for (id, key) in data.keys.ok_or(Error::UptaneMissingKeys)? {
            self.verifier(service).add_key(id, key)?;
        }

        let verified = self.verify_tuf(service, RoleName::Root, signed)?;
        if self.persist_metadata {
            fs::create_dir_all(format!("{}/{}", self.metadata_path, service))?;
            Util::write_file(&format!("{}/{}/root.json", self.metadata_path, service), &json)?;
        }
        Ok(verified)
    }

    /// Verify the signed TUF data using the current verifier's keys.
    fn verify_tuf(&mut self, service: Service, role: RoleName, signed: TufSigned) -> Result<Verified, Error> {
        let data = json::from_value::<RoleData>(signed.signed.clone())?;
        let new_ver = self.verifier(service).verify_signed(role, signed)?;
        let old_ver = self.verifier(service).set_version(role, new_ver)?;
        Ok(Verified { role: role, data: data, new_ver: new_ver, old_ver: old_ver })
    }

    /// Send a signed manifest with a list of signed objects to the Director server.
    pub fn put_manifest(&mut self, client: &Client, signed: Vec<TufSigned>) -> Result<(), Error> {
        let ecus = EcuManifests { primary_ecu_serial: self.primary_ecu.clone(), ecu_version_manifest: signed };
        let manifest = self.private_key.sign_data(json::to_value(ecus)?, self.sig_type)?;
        Ok(self.put(client, Service::Director, "manifest", json::to_vec(&manifest)?)?)
    }

    /// Sign the primary's `EcuVersion` for sending to the Director server.
    pub fn signed_version(&self, custom: Option<EcuCustom>) -> Result<TufSigned, Error> {
        let version = OstreePackage::get_latest(&self.primary_ecu)?.into_version(custom);
        self.private_key.sign_data(json::to_value(version)?, self.sig_type)
    }

    /// Extract a list of `OstreePackage`s from the targets.json metadata.
    pub fn extract_packages(targets: HashMap<String, TufMeta>, treehub: &Url) -> Vec<OstreePackage> {
        targets.into_iter()
            .filter_map(|(refname, mut meta)| {
                if let Some(commit) = meta.hashes.remove("sha256") {
                    let ecu = meta.custom.expect("custom field").ecuIdentifier;
                    Some(OstreePackage::new(ecu, refname, commit, "".into(), treehub))
                } else {
                    error!("couldn't get sha256 for {}", refname);
                    None
                }
            }).collect::<Vec<_>>()
    }
}


/// Store the keys and role data used for verifying uptane metadata.
#[derive(Default)]
pub struct Verifier {
    trusted_root_keys: HashSet<String>,

    keys:  HashMap<String, Key>,
    roles: HashMap<RoleName, RoleMeta>,
}

impl Verifier {
    pub fn new(trusted_root_keys: HashSet<String>) -> Self {
        Verifier { trusted_root_keys: trusted_root_keys, keys: HashMap::default(), roles: HashMap::default() }
    }

    pub fn add_meta(&mut self, role: RoleName, meta: RoleMeta) -> Result<(), Error> {
        trace!("adding role to verifier: {}", role);
        if role == RoleName::Root {
            let diff = meta.keyids.difference(&self.trusted_root_keys).collect::<HashSet<_>>();
            if diff.len() > 0 {
                return Err(Error::UptaneTrust(format!("unknown root keys: {:?}", diff)));
            }
        }

        if self.roles.get(&role).is_some() {
            Err(Error::UptaneRole(format!("{} already exists", role)))
        } else if meta.threshold < 1 {
            Err(Error::UptaneThreshold(format!("{} threshold too low", role)))
        } else {
            self.roles.insert(role, meta);
            Ok(())
        }
    }

    pub fn add_key(&mut self, id: String, key: Key) -> Result<(), Error> {
        trace!("adding key_id to verifier: {}", id);
        if id != key.key_id()? {
            Err(Error::TufKeyId(format!("wrong key_id: {}", id)))
        } else if self.keys.get(&id).is_some() {
            Err(Error::TufKeyId(format!("key_id already exists: {}", id)))
        } else {
            self.keys.insert(id, key);
            Ok(())
        }
    }

    pub fn get_version(&self, role: RoleName) -> Result<u64, Error> {
        let meta = self.roles.get(&role).ok_or_else(|| Error::UptaneRole(format!("no such role: {}", role)))?;
        Ok(meta.version)
    }

    pub fn set_version(&mut self, role: RoleName, version: u64) -> Result<u64, Error> {
        let meta = self.roles.get_mut(&role).ok_or_else(|| Error::UptaneRole(format!("no such role: {}", role)))?;
        let old = meta.version;
        trace!("updating {} version from {} to {}", role, old, version);
        meta.version = version;
        Ok(old)
    }

    /// Verify the signed data then return the version.
    pub fn verify_signed(&self, role: RoleName, signed: TufSigned) -> Result<u64, Error> {
        self.verify_signatures(role, &signed)?;
        let tuf_role = json::from_value::<TufRole>(signed.signed)?;
        if role != tuf_role._type {
            Err(Error::UptaneRole(format!("expected `{}`, got `{}`", role, tuf_role._type)))
        } else if tuf_role.expired() {
            Err(Error::UptaneExpired)
        } else if tuf_role.version < self.get_version(role)? {
            Err(Error::UptaneVersion)
        } else {
            Ok(tuf_role.version)
        }
    }

    /// Verify that a role-defined threshold of signatures successfully validate.
    pub fn verify_signatures(&self, role: RoleName, signed: &TufSigned) -> Result<(), Error> {
        let meta = self.roles.get(&role).ok_or_else(|| Error::UptaneRole(format!("no such role: {}", role)))?;
        let cjson = canonicalize_json(&json::to_vec(&signed.signed)?)?;
        let valid = signed.signatures
            .iter()
            .filter(|sig| meta.keyids.contains(&sig.keyid))
            .filter(|sig| self.verify_data(&cjson, sig))
            .map(|sig| &sig.keyid)
            .collect::<HashSet<_>>();

        let meta = self.roles.get(&role).ok_or_else(|| Error::UptaneRole(format!("no such role: {}", role)))?;
        if (valid.len() as u64) < meta.threshold {
            Err(Error::UptaneThreshold(format!("{} of {} ok", valid.len(), meta.threshold)))
        } else {
            Ok(())
        }
    }

    /// Verify that the signature matches the data.
    pub fn verify_data(&self, data: &[u8], sig: &Signature) -> bool {
        let verify = || -> Result<bool, Error> {
            let key = self.keys.get(&sig.keyid).ok_or_else(|| Error::KeyNotFound(sig.keyid.clone()))?;
            match key.keytype {
                KeyType::Ed25519 => {
                    let sig = Vec::from_hex(&sig.sig)?;
                    let key = Vec::from_hex(&key.keyval.public)?;
                    Ok(SignatureType::Ed25519.verify_msg(data, &key, &sig))
                }

                KeyType::Rsa => {
                    let sig = base64::decode(&sig.sig)?;
                    let pem = pem::parse(&key.keyval.public)?;
                    Ok(SignatureType::RsaSsaPss.verify_msg(data, &pem.contents, &sig))
                }
            }
        };

        match verify() {
            Ok(true)  => { trace!("successful verification: {}", sig.keyid); true }
            Ok(false) => { trace!("failed verification: {}", sig.keyid); false }
            Err(err)  => { trace!("failed verification for {}: {}", sig.keyid, err); false }
        }
    }
}


/// Encapsulate successfully verified data with additional metadata.
pub struct Verified {
    pub role: RoleName,
    pub data: RoleData,
    pub new_ver: u64,
    pub old_ver: u64,
}

impl Verified {
    pub fn is_new(&self) -> bool {
        self.new_ver > self.old_ver
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use pem;
    use std::collections::HashMap;

    use datatype::{EcuManifests, EcuVersion, TufCustom, TufMeta, TufSigned};
    use http::TestClient;


    fn trusted_director() -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert("4fc5bb052124eeed6fa23ac335c4fc17259d14f3e48ed89464402af28a76808d".into());
        set
    }

    fn trusted_repo() -> HashSet<String> {
        HashSet::new()
    }

    fn new_uptane(director_root_keys: HashSet<String>, repo_root_keys: HashSet<String>) -> Uptane {
        Uptane {
            director_server: "http://localhost:8001".parse().unwrap(),
            repo_server:     "http://localhost:8002".parse().unwrap(),
            metadata_path:   "[unused]".into(),
            persist_metadata: false,

            primary_ecu: "test-primary-serial".into(),
            device_id: "uptane-test".into(),
            private_key: PrivateKey {
                keyid:   "e453c713367595e1a9e5c1de8b2c039fe4178094bdaf2d52b1993fdd1a76ee26".into(),
                der_key: pem::parse("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdC9QttkMbF5qB\n2plVU2hhG2sieXS2CVc3E8rm/oYGc9EHnlPMcAuaBtn9jaBo37PVYO+VFInzMu9f\nVMLm7d/hQxv4PjTBpkXvw1Ad0Tqhg/R8Lc4SXPxWxlVhg0ahLn3kDFQeEkrTNW7k\nxpAxWiE8V09ETcPwyNhPfcWeiBePwh8ySJ10IzqHt2kXwVbmL4F/mMX07KBYWIcA\n52TQLs2VhZLIaUBv9ZBxymAvogGz28clx7tHOJ8LZ/daiMzmtv5UbXPdt+q55rLJ\nZ1TuG0CuRqhTOllXnIvAYRQr6WBaLkGGbezQO86MDHBsV5TsG6JHPorrr6ogo+Lf\npuH6dcnHAgMBAAECggEBAMC/fs45fzyRkXYn4srHh14d5YbTN9VAQd/SD3zrdn0L\n4rrs8Y90KHmv/cgeBkFMx+iJtYBev4fk41xScf2icTVhKnOF8sTls1hGDIdjmeeb\nQ8ZAvs++a39TRMJaEW2dN8NyiKsMMlkH3+H3z2ZpfE+8pm8eDHza9dwjBP6fF0SP\nV1XPd2OSrJlvrgBrAU/8WWXYSYK+5F28QtJKsTuiwQylIHyJkd8cgZhgYXlUVvTj\nnHFJblpAT0qphji7p8G4Ejg+LNxu/ZD+D3wQ6iIPgKFVdC4uXmPwlf1LeYqXW0+g\ngTmHY7a/y66yn1H4A5gyfx2EffFMQu0Sl1RqzDVYYjECgYEA9Hy2QsP3pxW27yLs\nCu5e8pp3vZpdkNA71+7v2BVvaoaATnsSBOzo3elgRYsN0On4ObtfQXB3eC9poNuK\nzWxj8bkPbVOCpSpq//sUSqkh/XCmAhDl78BkgmWDb4EFEgcAT2xPBTHkb70jVAXB\nE1HBwsBcXhdxzRt8IYiBG+68d/8CgYEA53SJYpJ809lfpAG0CU986FFD7Fi/SvcX\n21TVMn1LpHuH7MZ2QuehS0SWevvspkIUm5uT3PrhTxdohAInNEzsdeHhTU11utIO\nrKnrtgZXKsBG4idsHu5ZQzp4n3CBEpfPFbOtP/UEKI/IGaJWGXVgG4J6LWmQ9LK9\nilNTaOUQ7jkCgYB+YP0B9DTPLN1cLgwf9mokNA7TdrkJA2r7yuo2I5ZtVUt7xghh\nfWk+VMXMDP4+UMNcbGvn8s/+01thqDrOx0m+iO/djn6JDC01Vz98/IKydImLpdqG\nHUiXUwwnFmVdlTrm01DhmZHA5N8fLr5IU0m6dx8IEExmPt/ioaJDoxvPVwKBgC+8\n1H01M3PKWLSN+WEWOO/9muHLaCEBF7WQKKzSNODG7cEDKe8gsR7CFbtl7GhaJr/1\ndajVQdU7Qb5AZ2+dEgQ6Q2rbOBYBLy+jmE8hvaa+o6APe3hhtp1sGObhoG2CTB7w\nwSH42hO3nBDVb6auk9T4s1Rcep5No1Q9XW28GSLZAoGATFlXg1hqNKLO8xXq1Uzi\nkDrN6Ep/wq80hLltYPu3AXQn714DVwNa3qLP04dAYXbs9IaQotAYVVGf6N1IepLM\nfQU6Q9fp9FtQJdU+Mjj2WMJVWbL0ihcU8VZV5TviNvtvR1rkToxSLia7eh39AY5G\nvkgeMZm7SwqZ9c/ZFnjJDqc=\n-----END PRIVATE KEY-----").unwrap().contents
            },
            sig_type: SignatureType::RsaSsaPss,

            director_verifier: Verifier::new(director_root_keys),
            repo_verifier:     Verifier::new(repo_root_keys),
        }
    }

    fn extract_custom(targets: HashMap<String, TufMeta>) -> HashMap<String, TufCustom> {
        let mut out = HashMap::new();
        for (file, meta) in targets {
            let _ = meta.custom.map(|c| out.insert(file, c));
        }
        out
    }


    #[test]
    fn test_read_manifest() {
        let bytes = Util::read_file("tests/uptane/manifest.json").expect("couldn't read manifest.json");
        let signed = json::from_slice::<TufSigned>(&bytes).expect("couldn't load manifest");
        let mut ecus = json::from_value::<EcuManifests>(signed.signed).expect("couldn't load signed manifest");
        assert_eq!(ecus.primary_ecu_serial, "<primary_ecu_serial>");
        assert_eq!(ecus.ecu_version_manifest.len(), 1);
        let ver0 = ecus.ecu_version_manifest.pop().unwrap();
        let ecu0 = json::from_value::<EcuVersion>(ver0.signed).expect("couldn't load first manifest");
        assert_eq!(ecu0.installed_image.filepath, "<ostree_branch>-<ostree_commit>");
    }

    #[test]
    fn test_untrusted_root() {
        let mut uptane = new_uptane(HashSet::new(), HashSet::new());
        let client = TestClient::from_paths(&["tests/uptane/root.json"]);
        assert!(uptane.get_root(&client, Service::Director).is_err());
    }

    #[test]
    fn test_get_targets() {
        let mut uptane = new_uptane(trusted_director(), trusted_repo());
        let client = TestClient::from_paths(&[
            "tests/uptane/root.json",
            "tests/uptane/targets.json",
        ]);
        assert!(uptane.get_root(&client, Service::Director).expect("get_root").is_new());
        let verified = uptane.get_director(&client, RoleName::Targets).expect("get targets");
        assert!(verified.is_new());

        let targets = verified.data.targets.expect("missing targets");
        targets.get("/file.img").map(|meta| {
            assert_eq!(meta.length, 1337);
            let hash = meta.hashes.get("sha256").expect("sha256 hash");
            assert_eq!(hash, "dd250ea90b872a4a9f439027ac49d853c753426f71f61ae44c2f360a16179fb9");
        }).expect("get /file.img");
        let custom = extract_custom(targets);
        let image  = custom.get("/file.img").expect("get /file.img custom");
        assert_eq!(image.ecuIdentifier, "some-ecu-id");
    }

    #[test]
    fn test_get_snapshot() {
        let mut uptane = new_uptane(trusted_director(), trusted_repo());
        let client = TestClient::from_paths(&[
            "tests/uptane/root.json",
            "tests/uptane/snapshot.json",
        ]);
        assert!(uptane.get_root(&client, Service::Director).expect("couldn't get_root").is_new());
        let verified = uptane.get_director(&client, RoleName::Snapshot).expect("couldn't get snapshot");
        let metadata = verified.data.meta.as_ref().expect("missing meta");
        assert!(verified.is_new());
        let meta = metadata.get("targets.json").expect("no targets.json metadata");
        assert_eq!(meta.length, 741);
        let hash = meta.hashes.get("sha256").expect("couldn't get sha256 hash");
        assert_eq!(hash, "b10b36997574e6898dda4cfeb61c5f286d84dfa4be807950f14996cd476e6305");
    }

    #[test]
    fn test_get_timestamp() {
        let mut uptane = new_uptane(trusted_director(), trusted_repo());
        let client = TestClient::from_paths(&[
            "tests/uptane/root.json",
            "tests/uptane/timestamp.json",
        ]);
        assert!(uptane.get_root(&client, Service::Director).expect("get_root failed").is_new());
        let verified = uptane.get_director(&client, RoleName::Timestamp).expect("couldn't get timestamp");
        let metadata = verified.data.meta.as_ref().expect("missing meta");
        assert!(verified.is_new());
        let meta = metadata.get("snapshot.json").expect("no snapshot.json metadata");
        assert_eq!(meta.length, 784);
    }
}
