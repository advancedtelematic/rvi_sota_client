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
    RsaSsaPss,
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
            "ed25519"    => Ok(KeyType::Ed25519),
            "rsassa-pss" => Ok(KeyType::RsaSsaPss),
            _ => Err(Error::UptaneInvalidKeyType)
        }
    }
}

impl KeyType {
    pub fn verify(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> Result<(), Error> {
        match *self {
            KeyType::Ed25519 => {
                debug!("verifying using Ed25519: {}", str::from_utf8(key).unwrap_or("[raw bytes]"));
                if ed25519::verify(msg, key, sig) {
                    Ok(())
                } else {
                    Err(Error::UptaneVerifySignatures)
                }
            }

            KeyType::RsaSsaPss => {
                debug!("verifying using RSA SSA-PPS: {}", str::from_utf8(key).unwrap_or("[raw bytes]"));
                let verify = Rsa::public_key_from_pem(&key)
                    .and_then(PKey::from_rsa)
                    .and_then(|k| OpenSslVerifier::new(MessageDigest::sha256(), &k)
                        .and_then(|mut v| v.update(&msg).map(|_| v))
                        .and_then(|v| v.finish(&sig))
                    )?;

                if verify {
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

        let signed = json::to_string(&metadata.signed)?;
        let mut valid_count = 0;
        for sig in &metadata.signatures {
            self.keys.get(&sig.keyid)
                .map(|key| {
                    let ref public = key.keyval.public;
                    key.keytype
                        .verify(signed.as_bytes(), public.as_bytes(), sig.sig.as_bytes())
                        .map(|_| {
                            trace!("successful verification with: {}", public);
                            valid_count += 1;
                        })
                        .unwrap_or_else(|err| trace!("failed verification for {} with: {}", public, err));
                })
                .unwrap_or_else(|| debug!("couldn't find key: {}", sig.keyid));
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

    // signing key: 0wm+qYNKH2v7VUMy0lEz0ZfOEtEbdbDNwklW5PPLs4WpCLVDpXuapnO3XZQ9i1wV3aiIxi1b5TxVeVeulbyUyw==
    const ED25519_PUB: &'static [u8; 44] = b"qQi1Q6V7mqZzt12UPYtcFd2oiMYtW+U8VXlXrpW8lMs=";

    const RSA_2048_PUB: &'static [u8; 450] = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7CADRxUJDe2254+F16rw\nMeI3n0d1My4TRNIKQRY5LttWKgS5hYYyAM4zvokYQlV01x3iyxibrZDDdl4Egm0E\nQPDG6q1NTYG+4LE5VJKYVOtlQXdWWQBXjMv6wP28EfMQcgL5uZ0tUVA8ibw80nAI\ncrNM6ZfFhEMe4ABS3ti3lXWYAL0gNmbZoyxvVUWUnwEpolFQJ75Ubdn1KOSaCAxD\nOCtZaXa6iNiMQEXLsmOADFru8FCkiK4eRs5wdnV4hF01y8wCnVrNq8LrymxEzWxQ\nF8Up4fqosweBwbZrbk/IXofuA4GpDXfoF309BmfW+GVguVs3pPgw1w4Z5f3KOTiv\nBQIDAQAB\n-----END PUBLIC KEY-----";

    #[test]
    fn test_rsa_verify() {
        // signed with openssl using the above key
        let msg = b"hello";
        let sig = "YCvXXrxeqgSV/KDPyHQHOyKpwcSPi0ZYweVDVkMuvAuEt9v+ujwvGULkfk1JGapN+qwDrekXsgzGXF0uL1rhsGMrh/RMh2+R86Pmyr+UTb/PVVFk1a5HpXk1v+97DkG7hpAcCD3MHqHCf/STXab/YbB2atYXYxNv4oq3ahCa0L/uGYmScPB2AXiAZbB/QJjYC6W02WtIOWhixF8uA5wEvgUmBsEBtDQkjtMfBVpQ3bLeBVvrEJXYHW3bL0GJal860KH6eS//wOLGDtcYZxPxcvZMtsWSrE1zPBrrCedsZByCg2NRqkuF3s/cTJv5unKfPgpop8yU6aCMmVIgfnEKcA==";
        let sig_raw = sig.from_base64().expect("couldn't parse signed from Base64");
        KeyType::RsaSsaPss.verify(msg, RSA_2048_PUB, &sig_raw).expect("couldn't verify message");

        {
            let mut bad_msg = msg.clone();
            bad_msg[0] = msg[0] ^ 0x01;
            if KeyType::RsaSsaPss.verify(&bad_msg, RSA_2048_PUB, &sig_raw).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
        {
            let mut bad_sig = sig_raw.clone();
            bad_sig[0] = sig_raw[0] ^ 0x01;
            if KeyType::RsaSsaPss.verify(msg, RSA_2048_PUB, &bad_sig).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
    }

    #[test]
    fn test_ed25519_verify() {
        let msg = b"hello";
        let sig = "/VniTdrxQlEXcx5QJGHqI7ptGwTq1wBThbfflb8SLRrEE4LQMkd5yBh/PWGvsU7cFNN+PNhFUZY4QwVq9p4MAg";
        let sig_raw = sig.from_base64().expect("couldn't parse signed from Base64");
        KeyType::Ed25519.verify(msg, &ED25519_PUB.from_base64().unwrap(), &sig_raw).expect("couldn't verify message");

        {
            let mut bad_msg = msg.clone();
            bad_msg[0] = msg[0] ^ 0x01;
            if KeyType::Ed25519.verify(&bad_msg, ED25519_PUB, &sig_raw).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
        {
            let mut bad_sig = sig_raw.clone();
            bad_sig[0] = sig_raw[0] ^ 0x01;
            if KeyType::Ed25519.verify(msg, ED25519_PUB, &bad_sig).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
    }
}
