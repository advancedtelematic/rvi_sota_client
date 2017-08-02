use base64;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hex::FromHex;
use json;
use pem;
use std::{mem, thread};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::net::SocketAddrV4;
use std::time::Duration;

use atomic::{Multicast, Payload, Payloads, Primary, Secondary, State, Step, StepData};
use images::ImageReader;
use datatype::{CanonicalJson, Config, EcuConfig, EcuCustom, EcuManifests, Error,
               InstallOutcome, Key, KeyType, Manifests, OstreePackage, PrivateKey, RoleData,
               RoleMeta, RoleName, Signature, SignatureType, TufSigned, Url, Util};
use http::{Client, Response};
use pacman::Credentials;


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
    pub private_key: PrivateKey,
    pub sig_type:    SignatureType,
    pub secondaries: Vec<EcuConfig>,
    pub manifests:   Manifests,

    pub director_verifier: Verifier,
    pub repo_verifier:     Verifier,

    pub atomic_wake_addr: SocketAddrV4,
    pub atomic_msg_addr:  SocketAddrV4,
    pub atomic_timeout:   Duration,
}

impl Uptane {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let der_key = Util::read_file(&config.uptane.private_key_path)?;
        let pub_key = Util::read_file(&config.uptane.public_key_path)?;
        let mut hasher = Sha256::new();
        hasher.input(&pub_key);

        let manifests = config.ecus.iter()
            .map(|ecu| Util::read_text(&ecu.manifest_path)
                 .and_then(|text| Ok((ecu.ecu_serial.clone(), json::from_str(&text)?))))
            .collect::<Result<Manifests, _>>()
            .map_err(|err| Error::Config(format!("couldn't read secondary manifest: {}", err)))?;

        let mut uptane = Uptane {
            director_server:  config.uptane.director_server.clone(),
            repo_server:      config.uptane.repo_server.clone(),
            metadata_path:    config.uptane.metadata_path.clone(),
            persist_metadata: true,

            primary_ecu: config.uptane.primary_ecu_serial.clone(),
            private_key: PrivateKey { keyid: hasher.result_str(), der_key: der_key },
            sig_type:    SignatureType::RsaSsaPss,
            secondaries: config.ecus.clone(),
            manifests:   manifests,

            director_verifier: Verifier::default(),
            repo_verifier:     Verifier::default(),

            atomic_wake_addr: *config.uptane.atomic_wake_up,
            atomic_msg_addr:  *config.uptane.atomic_message,
            atomic_timeout: Duration::from_secs(config.uptane.atomic_timeout_sec),
        };

        uptane.add_root_keys(Service::Director)?;
        uptane.add_root_keys(Service::Repo)?;
        Ok(uptane)
    }

    /// Returns a URL based on the uptane service.
    fn endpoint(&self, service: Service, endpoint: &str) -> Url {
        match service {
            Service::Director => self.director_server.join(&format!("/{}", endpoint)),
            Service::Repo     => self.repo_server.join(&format!("/{}", endpoint))
        }
    }

    /// Returns the respective key verifier for an uptane service.
    fn verifier(&mut self, service: Service) -> &mut Verifier {
        match service {
            Service::Director => &mut self.director_verifier,
            Service::Repo     => &mut self.repo_verifier
        }
    }

    /// Add the keys from a service's local `root.json` metadata to its verifier.
    fn add_root_keys(&mut self, service: Service) -> Result<(), Error> {
        trace!("adding root keys for {}", service);
        let json = Util::read_file(&format!("{}/{}/root.json", self.metadata_path, service))?;
        let signed = json::from_slice::<TufSigned>(&json)?;
        let data = json::from_value::<RoleData>(signed.signed)?;
        for (role, meta) in data.roles.ok_or(Error::UptaneMissingRoles)? {
            self.verifier(service).add_meta(role, meta)?;
        }
        for (id, key) in data.keys.ok_or(Error::UptaneMissingKeys)? {
            self.verifier(service).add_key(id, key)?;
        }
        Ok(())
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

    /// Fetch the latest role metadata from the Director service.
    pub fn get_director(&mut self, client: &Client, role: RoleName) -> Result<Verified, Error> {
        self.get_metadata(client, Service::Director, role)
    }

    /// Fetch the latest role metadata from the Repo service.
    pub fn get_repo(&mut self, client: &Client, role: RoleName) -> Result<Verified, Error> {
        self.get_metadata(client, Service::Repo, role)
    }

    /// Fetch the latest role metadata from the given service.
    pub fn get_metadata(&mut self, client: &Client, service: Service, role: RoleName) -> Result<Verified, Error> {
        trace!("getting {} role from {} service", role, service);
        let json = self.get(client, service, &format!("{}.json", role))?;
        let signed = json::from_slice::<TufSigned>(&json)?;
        let mut verified = self.verifier(service).verify_signed(role, signed)?;
        if verified.is_new() && self.persist_metadata {
            let dir = format!("{}/{}", self.metadata_path, service);
            Util::write_file(&format!("{}/{}.json", dir, role), &json)?;
            Util::write_file(&format!("{}/{}.{}.json", dir, verified.new_ver, role), &json)?;
            verified.json = Some(json);
        }
        Ok(verified)
    }

    /// Download an image from the `Director` repository.
    pub fn fetch_director(&mut self, client: &Client, refname: &str) -> Result<ImageReader, Error> {
        let data = self.get(client, Service::Director, refname)?;
        Util::write_file(&format!("/tmp/sota-reader-images/{}", refname), &data)?;
        ImageReader::new(refname.into(), "/tmp/sota-reader-images".into())
    }

    /// Download an image from the `Repo` repository.
    pub fn fetch_repo(&mut self, client: &Client, refname: &str) -> Result<ImageReader, Error> {
        let data = self.get(client, Service::Repo, &format!("targets/{}", refname))?;
        Util::write_file(&format!("/tmp/sota-reader-images/{}", refname), &data)?;
        ImageReader::new(refname.into(), "/tmp/sota-reader-images".into())
    }

    /// Generate a new signed TUF installation report.
    pub fn signed_report(&mut self, custom: Option<EcuCustom>) -> Result<TufSigned, Error> {
        let version = OstreePackage::get_latest(&self.primary_ecu)?.into_version(custom);
        self.private_key.sign_data(json::to_value(version)?, self.sig_type)
    }

    /// Send a signed manifest to `Director` containing individually signed ECU manifests.
    pub fn put_manifest(&mut self, client: &Client, manifests: Option<Manifests>) -> Result<(), Error> {
        let mut versions = self.manifests.clone();
        if let Some(manifests) = manifests {
            for (serial, version) in manifests {
                let _ = versions.insert(serial, version);
            }
        }
        let ecus = EcuManifests { primary_ecu_serial: self.primary_ecu.clone(), ecu_version_manifests: versions };
        let manifest = self.private_key.sign_data(json::to_value(ecus)?, self.sig_type)?;
        Ok(self.put(client, Service::Director, "manifest", json::to_vec(&manifest)?)?)
    }

    /// Start a transaction to install the verified targets to their respective ECUs.
    pub fn install(&mut self, verified: Verified, treehub: Url, creds: Credentials) -> Result<(Manifests, bool), Error> {
        let (images, payloads) = self.fetch_targets(&verified, &treehub, creds)?;
        let bus = Box::new(Multicast::new(self.atomic_wake_addr, self.atomic_msg_addr)?);
        let mut primary = Primary::new(payloads, self.manifests.clone(), images, bus, self.atomic_timeout, None);

        match primary.commit() {
            Ok(()) => Ok((primary.into_manifests(), true)),
            Err(Error::AtomicAbort(_)) |
            Err(Error::AtomicTimeout)  => Ok((primary.into_manifests(), false)),
            Err(err) => Err(err)
        }
    }

    fn fetch_targets(&mut self, verified: &Verified, treehub: &Url, creds: Credentials)
                     -> Result<(HashMap<String, ImageReader>, Payloads), Error> {
        let mut primary_pkg = None;
        let mut images = HashMap::new();
        let targets = verified.data.targets.as_ref()
            .ok_or_else(|| Error::UptaneTargets("no targets found".into()))?;

        let mut payloads = targets.iter()
            .map(|(refname, meta)| if let Some(ref custom) = meta.custom {
                let ecu_serial = custom.ecuIdentifier.clone();

                if let Ok(mut reader) = self.fetch_director(&*creds.client, refname) {
                    let meta = reader.image_meta()?;
                    images.insert(meta.image_name.clone(), reader);
                    Ok((ecu_serial, hashmap!{ State::Fetch => Payload::ImageMeta(json::to_vec(&meta)?) }))
                } else if let Ok(mut reader) = self.fetch_repo(&*creds.client, refname) {
                    let meta = reader.image_meta()?;
                    images.insert(meta.image_name.clone(), reader);
                    Ok((ecu_serial, hashmap!{ State::Fetch => Payload::ImageMeta(json::to_vec(&meta)?) }))
                } else {
                    let pkg = OstreePackage::from_meta(meta.clone(), refname.clone(), "sha256", treehub)?;
                    if ecu_serial == self.primary_ecu {
                        primary_pkg = Some(pkg.clone());
                    }
                    Ok((ecu_serial, hashmap!{ State::Fetch => Payload::OstreePackage(json::to_vec(&pkg)?) }))
                }
            } else {
                Err(Error::UptaneTargets(format!("refname {} has no custom field", refname)))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        if let Some(pkg) = primary_pkg {
            let bus = Box::new(Multicast::new(self.atomic_wake_addr, self.atomic_msg_addr)?);
            let inst = Box::new(PrimaryInstaller {
                serial: self.primary_ecu.clone(),
                pkg: pkg,
                sig_type: self.sig_type,
                priv_key: self.private_key.clone(),
                credentials: creds
            });
            let mut ecu = Secondary::new(self.primary_ecu.clone(), bus, inst, self.atomic_timeout, None);
            thread::spawn(move || ecu.listen());
        }

        if let Some(ref json) = verified.json {
            for (_, mut states) in payloads.iter_mut() {
                states.insert(State::Verify, Payload::UptaneMetadata(json.clone()));
            }
        }

        Ok((images, payloads))
    }
}


/// Define an installer for an `OstreePackage` as part of a transaction.
pub struct PrimaryInstaller {
    serial: String,
    pkg: OstreePackage,
    sig_type: SignatureType,
    priv_key: PrivateKey,
    credentials: Credentials,
}

impl PrimaryInstaller {
    fn signed(&self, outcome: InstallOutcome) -> Result<Option<StepData>, Error> {
        let custom = EcuCustom::from_result(outcome.into_result(self.serial.clone()));
        let version = OstreePackage::get_latest(&self.pkg.ecu_serial)?.into_version(Some(custom));
        Ok(Some(StepData::TufReport(self.priv_key.sign_data(json::to_value(version)?, self.sig_type)?)))
    }
}

impl Step for PrimaryInstaller {
    fn step(&mut self, state: State, _: Option<Payload>) -> Result<Option<StepData>, Error> {
        match state {
            State::Idle | State::Ready | State::Verify | State::Fetch => Ok(None),
            State::Commit => self.signed(self.pkg.install(&self.credentials)?),
            State::Abort  => self.signed(InstallOutcome::error("aborted".into()))
        }
    }
}


/// Store the keys and role data used for verifying uptane metadata.
#[derive(Default)]
pub struct Verifier {
    keys:  HashMap<String, Key>,
    roles: HashMap<RoleName, RoleMeta>,
}

impl Verifier {
    pub fn add_meta(&mut self, role: RoleName, meta: RoleMeta) -> Result<(), Error> {
        trace!("adding role to verifier: {}", role);
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

    /// Verify that the signed data is valid.
    pub fn verify_signed(&mut self, role: RoleName, signed: TufSigned) -> Result<Verified, Error> {
        let current = {
            let meta = self.roles.get(&role).ok_or_else(|| Error::UptaneRole(format!("{} not found", role)))?;
            self.verify_signatures(&meta, &signed)?;
            meta.version
        };

        let data = json::from_value::<RoleData>(signed.signed)?;
        if data._type != role {
            Err(Error::UptaneRole(format!("expected `{}`, got `{}`", role, data._type)))
        } else if data.expired() {
            Err(Error::UptaneExpired)
        } else if data.version < current {
            Err(Error::UptaneVersion)
        } else if data.version > current {
            let meta = self.roles.get_mut(&role).expect("get_mut role");
            let old = mem::replace(&mut meta.version, data.version);
            debug!("{} version updated from {} to {}", role, old, data.version);
            Ok(Verified { role: role, data: data, json: None, new_ver: meta.version, old_ver: old })
        } else {
            Ok(Verified { role: role, data: data, json: None, new_ver: current, old_ver: current })
        }
    }

    /// Verify that a role-defined threshold of signatures successfully validate.
    pub fn verify_signatures(&self, meta: &RoleMeta, signed: &TufSigned) -> Result<(), Error> {
        let cjson = CanonicalJson::into_bytes(json::to_value(&signed.signed)?)?;
        let valid = signed.signatures
            .iter()
            .filter(|sig| meta.keyids.contains(&sig.keyid))
            .filter(|sig| self.verify_data(&cjson, sig))
            .map(|sig| &sig.sig)
            .collect::<HashSet<_>>();

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
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Verified {
    pub role: RoleName,
    pub data: RoleData,
    pub json: Option<Vec<u8>>,
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
    use std::net::Ipv4Addr;

    use datatype::{EcuManifests, EcuVersion, TufCustom, TufMeta, TufSigned};
    use http::TestClient;


    fn new_uptane() -> Uptane {
        let mut uptane = Uptane {
            director_server:  "http://localhost:8001".parse().unwrap(),
            repo_server:      "http://localhost:8002".parse().unwrap(),
            metadata_path:    "tests/uptane_basic".into(),
            persist_metadata: false,

            primary_ecu: "test-primary-serial".into(),
            private_key: PrivateKey {
                keyid:   "e453c713367595e1a9e5c1de8b2c039fe4178094bdaf2d52b1993fdd1a76ee26".into(),
                der_key: pem::parse("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdC9QttkMbF5qB\n2plVU2hhG2sieXS2CVc3E8rm/oYGc9EHnlPMcAuaBtn9jaBo37PVYO+VFInzMu9f\nVMLm7d/hQxv4PjTBpkXvw1Ad0Tqhg/R8Lc4SXPxWxlVhg0ahLn3kDFQeEkrTNW7k\nxpAxWiE8V09ETcPwyNhPfcWeiBePwh8ySJ10IzqHt2kXwVbmL4F/mMX07KBYWIcA\n52TQLs2VhZLIaUBv9ZBxymAvogGz28clx7tHOJ8LZ/daiMzmtv5UbXPdt+q55rLJ\nZ1TuG0CuRqhTOllXnIvAYRQr6WBaLkGGbezQO86MDHBsV5TsG6JHPorrr6ogo+Lf\npuH6dcnHAgMBAAECggEBAMC/fs45fzyRkXYn4srHh14d5YbTN9VAQd/SD3zrdn0L\n4rrs8Y90KHmv/cgeBkFMx+iJtYBev4fk41xScf2icTVhKnOF8sTls1hGDIdjmeeb\nQ8ZAvs++a39TRMJaEW2dN8NyiKsMMlkH3+H3z2ZpfE+8pm8eDHza9dwjBP6fF0SP\nV1XPd2OSrJlvrgBrAU/8WWXYSYK+5F28QtJKsTuiwQylIHyJkd8cgZhgYXlUVvTj\nnHFJblpAT0qphji7p8G4Ejg+LNxu/ZD+D3wQ6iIPgKFVdC4uXmPwlf1LeYqXW0+g\ngTmHY7a/y66yn1H4A5gyfx2EffFMQu0Sl1RqzDVYYjECgYEA9Hy2QsP3pxW27yLs\nCu5e8pp3vZpdkNA71+7v2BVvaoaATnsSBOzo3elgRYsN0On4ObtfQXB3eC9poNuK\nzWxj8bkPbVOCpSpq//sUSqkh/XCmAhDl78BkgmWDb4EFEgcAT2xPBTHkb70jVAXB\nE1HBwsBcXhdxzRt8IYiBG+68d/8CgYEA53SJYpJ809lfpAG0CU986FFD7Fi/SvcX\n21TVMn1LpHuH7MZ2QuehS0SWevvspkIUm5uT3PrhTxdohAInNEzsdeHhTU11utIO\nrKnrtgZXKsBG4idsHu5ZQzp4n3CBEpfPFbOtP/UEKI/IGaJWGXVgG4J6LWmQ9LK9\nilNTaOUQ7jkCgYB+YP0B9DTPLN1cLgwf9mokNA7TdrkJA2r7yuo2I5ZtVUt7xghh\nfWk+VMXMDP4+UMNcbGvn8s/+01thqDrOx0m+iO/djn6JDC01Vz98/IKydImLpdqG\nHUiXUwwnFmVdlTrm01DhmZHA5N8fLr5IU0m6dx8IEExmPt/ioaJDoxvPVwKBgC+8\n1H01M3PKWLSN+WEWOO/9muHLaCEBF7WQKKzSNODG7cEDKe8gsR7CFbtl7GhaJr/1\ndajVQdU7Qb5AZ2+dEgQ6Q2rbOBYBLy+jmE8hvaa+o6APe3hhtp1sGObhoG2CTB7w\nwSH42hO3nBDVb6auk9T4s1Rcep5No1Q9XW28GSLZAoGATFlXg1hqNKLO8xXq1Uzi\nkDrN6Ep/wq80hLltYPu3AXQn714DVwNa3qLP04dAYXbs9IaQotAYVVGf6N1IepLM\nfQU6Q9fp9FtQJdU+Mjj2WMJVWbL0ihcU8VZV5TviNvtvR1rkToxSLia7eh39AY5G\nvkgeMZm7SwqZ9c/ZFnjJDqc=\n-----END PRIVATE KEY-----").unwrap().contents
            },
            sig_type: SignatureType::RsaSsaPss,
            secondaries: Vec::new(),
            manifests: hashmap!{},

            director_verifier: Verifier::default(),
            repo_verifier:     Verifier::default(),

            atomic_wake_addr: SocketAddrV4::new(Ipv4Addr::new(232,0,0,101), 23211),
            atomic_msg_addr:  SocketAddrV4::new(Ipv4Addr::new(232,0,0,102), 23212),
            atomic_timeout:   Duration::from_secs(60),
        };
        uptane.add_root_keys(Service::Director).expect("add director root keys");
        uptane
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
        let bytes = Util::read_file("tests/uptane_basic/director/manifest.json").expect("couldn't read manifest.json");
        let signed = json::from_slice::<TufSigned>(&bytes).expect("couldn't load manifest");
        let ecus = json::from_value::<EcuManifests>(signed.signed).expect("couldn't load signed manifest");
        let serial = "<primary_ecu_serial>";
        assert_eq!(ecus.primary_ecu_serial, serial);
        assert_eq!(ecus.ecu_version_manifests.len(), 1);
        let ver0 = ecus.ecu_version_manifests.get(serial).unwrap();
        let ecu0 = json::from_value::<EcuVersion>(ver0.signed.clone()).expect("couldn't load first manifest");
        assert_eq!(ecu0.installed_image.filepath, "<ostree_branch>-<ostree_commit>");
    }

    #[test]
    fn test_get_targets() {
        let mut uptane = new_uptane();
        let client = TestClient::from_paths(&["tests/uptane_basic/director/targets.json"]);
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
        let mut uptane = new_uptane();
        let client = TestClient::from_paths(&["tests/uptane_basic/director/snapshot.json"]);
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
        let mut uptane = new_uptane();
        let client = TestClient::from_paths(&["tests/uptane_basic/director/timestamp.json"]);
        let verified = uptane.get_director(&client, RoleName::Timestamp).expect("couldn't get timestamp");
        let metadata = verified.data.meta.as_ref().expect("missing meta");
        assert!(verified.is_new());
        let meta = metadata.get("snapshot.json").expect("no snapshot.json metadata");
        assert_eq!(meta.length, 784);
    }
}
