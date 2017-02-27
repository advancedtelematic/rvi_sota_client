use cjson;
use crypto::ed25519;
use std::collections::HashMap;
use std::str::FromStr;

use datatype::{Error, Key, Metadata, Role, RoleData, SignedMeta, UptaneKeys, UptaneRoles};


#[allow(non_camel_case_types)]
#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum KeyType {
    ed25519
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyType::ed25519),
            _         => Err(Error::UptaneInvalidKeyType)
        }
    }
}

impl KeyType {
    pub fn verify(&self, key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        match *self {
            KeyType::ed25519 => ed25519::verify(msg, key, sig),
        }
    }
}


pub struct Verifier {
    keys:  UptaneKeys,
    roles: UptaneRoles,
}

impl Verifier {
    pub fn new() -> Self {
        Verifier {
            keys:  HashMap::new(),
            roles: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, key: Key) {
        self.keys.insert(key.id.clone(), key);
    }

    pub fn add_role(&mut self, role: Role, data: RoleData) {
        self.roles.insert(role, data);
    }

    pub fn verify(&self, role: Role, metadata: Metadata, min_version: u64) -> Result<(), Error> {
        self.verify_signatures(&role, &metadata)?;

        let meta = cjson::from_slice::<SignedMeta>(&metadata.signed)?;
        if meta._type != role {
            Err(Error::UptaneInvalidRole)
        } else if meta.expired()? {
            Err(Error::UptaneExpired)
        } else if meta.version < min_version {
            Err(Error::UptaneVersion)
        } else {
            Ok(())
        }
    }

    pub fn verify_signatures(&self, role: &Role, metadata: &Metadata) -> Result<(), Error> {
        if metadata.signatures.len() == 0 {
            return Err(Error::UptaneMissingSignatures);
        }

        let mut valid_count = 0;
        for sig in &metadata.signatures {
            match self.keys.get(&sig.keyid) {
                Some(key) => {
                    if !key.keytype.verify(&key.keyval.public, &metadata.signed, &sig.sig.as_bytes()) {
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
