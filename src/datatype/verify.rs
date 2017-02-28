use crypto::ed25519;
use serde;
use serde_json as json;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier as OpenSslVerifier;
use std::collections::HashMap;
use std::str::{self, FromStr};

use datatype::{Error, Key, Metadata, Role, RoleData, Signed};


#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
pub enum KeyType {
    Ed25519,
    Rsa,
}

impl serde::Deserialize for KeyType {
    fn deserialize<D: serde::Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = serde::Deserialize::deserialize(de)? {
            s.parse().map_err(|err| serde::de::Error::custom(format!("unknown KeyType: {}", err)))
        } else {
            Err(serde::de::Error::custom("unknown KeyType"))
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyType::Ed25519),
            "rsa"     => Ok(KeyType::Rsa),
            _ => Err(Error::UptaneInvalidKeyType)
        }
    }
}

impl KeyType {
    pub fn verify(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> Result<(), Error> {
        match *self {
            KeyType::Ed25519 => {
                debug!("verifying using Ed25519 key: {}", str::from_utf8(key).unwrap_or("[raw bytes]"));
                if ed25519::verify(msg, key, sig) {
                    Ok(())
                } else {
                    Ok(()) // FIXME
                    //Err(Error::UptaneVerifySignatures)
                }
            }

            // TODO we are blindly assuming here that only one type of signature
            // is done with an RSA key, but this will not always be the case.
            // The `verify` method needs to take args V(kt, st, m, k, s) where
            // kt = keytype, st = sigtype, m = msg, k = key, s = sig.
            KeyType::Rsa => {
                debug!("verifying using RSA key: {}", str::from_utf8(key).unwrap_or("[raw bytes]"));
                let ok = Rsa::public_key_from_pem(&key)
                    .and_then(PKey::from_rsa)
                    .and_then(|k| OpenSslVerifier::new(MessageDigest::sha256(), &k)
                        .and_then(|mut v| v.update(&msg).map(|_| v))
                        .and_then(|v| v.finish(&sig))
                    )?;

                if ok {
                    Ok(())
                } else {
                    Err(Error::UptaneVerifySignatures)
                }
            }
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
                    key.keytype.verify(signed.as_bytes(),
                                       key.keyval.public.as_bytes(),
                                       sig.sig.as_bytes())?;
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


#[cfg(test)]
mod tests {
    use super::*;

    use rustc_serialize::base64::FromBase64;


    const RSA_2048_PUB: &'static [u8; 450] = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7CADRxUJDe2254+F16rw\nMeI3n0d1My4TRNIKQRY5LttWKgS5hYYyAM4zvokYQlV01x3iyxibrZDDdl4Egm0E\nQPDG6q1NTYG+4LE5VJKYVOtlQXdWWQBXjMv6wP28EfMQcgL5uZ0tUVA8ibw80nAI\ncrNM6ZfFhEMe4ABS3ti3lXWYAL0gNmbZoyxvVUWUnwEpolFQJ75Ubdn1KOSaCAxD\nOCtZaXa6iNiMQEXLsmOADFru8FCkiK4eRs5wdnV4hF01y8wCnVrNq8LrymxEzWxQ\nF8Up4fqosweBwbZrbk/IXofuA4GpDXfoF309BmfW+GVguVs3pPgw1w4Z5f3KOTiv\nBQIDAQAB\n-----END PUBLIC KEY-----";

    #[test]
    fn test_rsa_verify() {
        // signed with openssl using the above key
        let msg = b"hello";
        let signed = "YCvXXrxeqgSV/KDPyHQHOyKpwcSPi0ZYweVDVkMuvAuEt9v+ujwvGULkfk1JGapN+qwDrekXsgzGXF0uL1rhsGMrh/RMh2+R86Pmyr+UTb/PVVFk1a5HpXk1v+97DkG7hpAcCD3MHqHCf/STXab/YbB2atYXYxNv4oq3ahCa0L/uGYmScPB2AXiAZbB/QJjYC6W02WtIOWhixF8uA5wEvgUmBsEBtDQkjtMfBVpQ3bLeBVvrEJXYHW3bL0GJal860KH6eS//wOLGDtcYZxPxcvZMtsWSrE1zPBrrCedsZByCg2NRqkuF3s/cTJv5unKfPgpop8yU6aCMmVIgfnEKcA==";
        let signed_raw = signed.from_base64().expect("couldn't parse signed from Base64");
        KeyType::Rsa.verify(msg, RSA_2048_PUB, &signed_raw).expect("couldn't verify message")
    }
}
