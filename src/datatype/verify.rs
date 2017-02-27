//use canonical_json as cjson;
use crypto::ed25519;
use serde_json as json;
use std::collections::HashMap;

use datatype::{Error, Key, Metadata, Role, RoleData, Signed};


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum KeyType {
    #[serde(rename = "ed25519")]
    Ed25519
}

impl KeyType {
    pub fn verify(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> bool {
        match *self {
            KeyType::Ed25519 => ed25519::verify(msg, key, sig),
        }
    }
}


pub struct Verifier {
    keys:  HashMap<String, Key>,
    roles: HashMap<Role, RoleData>
}

impl Verifier {
    pub fn new() -> Self {
        Verifier {
            keys:  HashMap::new(),
            roles: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, id: String, key: Key) {
        debug!("inserting to verifier: {}", id);
        self.keys.insert(id, key);
    }

    pub fn add_role(&mut self, role: Role, data: RoleData) {
        debug!("inserting role to verifier: {:?}", role);
        self.roles.insert(role, data);
    }

    pub fn verify(&self, role: &Role, metadata: &Metadata, min_version: u64) -> Result<(), Error> {
        self.verify_signatures(role, metadata)?;

        let signed = json::from_value::<Signed>(metadata.signed.clone())?;
        if signed._type != *role {
            Err(Error::UptaneInvalidRole)
        } else if signed.expired()? {
            Err(Error::UptaneExpired)
        } else if signed.version < min_version {
            Err(Error::UptaneVersion)
        } else {
            Ok(())
        }
    }

    pub fn verify_signatures(&self, role: &Role, metadata: &Metadata) -> Result<(), Error> {
        if metadata.signatures.is_empty() {
            return Err(Error::UptaneMissingSignatures);
        }

        let mut valid_count = 0;
        for sig in &metadata.signatures {
            match self.keys.get(&sig.keyid) {
                Some(key) => {
                    let signed = json::to_string(&metadata.signed)?;
                    if ! key.keytype.verify(signed.as_bytes(),
                                            key.keyval.public.as_bytes(),
                                            sig.sig.as_bytes()) {
                        return Err(Error::UptaneVerifySignatures);
                    }
                    valid_count += 1;
                },

                None => debug!("couldn't find key: {}", sig.keyid)
            }
        }

        let role = self.roles.get(role).ok_or(Error::UptaneUnknownRole)?;
        if valid_count < role.threshold {
            Err(Error::UptaneRoleThreshold)
        } else {
            Ok(())
        }
    }
}
