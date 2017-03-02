use crypto::ed25519;
use serde;
use serde_json as json;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Rsa, Padding};
use openssl::sign::{Signer, Verifier as OpensslVerifier};
use std::collections::HashMap;
use std::str::{self, FromStr};

use datatype::{Error, Key, Metadata, Role, RoleData, Signed, canonicalize_json};


pub struct PrivateKey {
    pub keyid: String,
    /// DER encoded private key
    pub priv_key: Vec<u8>,
}


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
            "ed25519" | "Ed25519"  => Ok(KeyType::Ed25519),
            "rsa"     | "RSA"      => Ok(KeyType::Rsa),
            _ => Err(Error::UptaneInvalidKeyType(s.to_string()))
        }
    }
}

#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
pub enum SignatureType {
    Ed25519,
    RsaSsaPss,
}

impl serde::Deserialize for SignatureType {
    fn deserialize<D: serde::Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = serde::Deserialize::deserialize(de)? {
            s.parse().map_err(|err| serde::de::Error::custom(format!("unknown SignatureType: {}", err)))
        } else {
            Err(serde::de::Error::custom("unknown SignatureType"))
        }
    }
}

impl FromStr for SignatureType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519"    => Ok(SignatureType::Ed25519),
            "rsassa-pss" => Ok(SignatureType::RsaSsaPss),
            _ => Err(Error::UptaneInvalidSignatureType(s.to_string()))
        }
    }
}

impl SignatureType {
    pub fn sign(&self, msg: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            SignatureType::RsaSsaPss => {
                let rsa = Rsa::private_key_from_der(&key)?;
                let priv_key = PKey::from_rsa(rsa)?;
                let mut signer = Signer::new(MessageDigest::sha256(), &priv_key)?;
                // magic number 6 taken from rsa.h in openssl
                signer.pkey_ctx_mut().set_rsa_padding(Padding::from_raw(6))?;
                signer.update(msg)?;
                let sig = signer.finish()?;
                Ok(sig)
            }
            _ => unimplemented!(),
        }
    }

    pub fn verify(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> Result<(), Error> {
        match *self {
            SignatureType::Ed25519 => {
                debug!("verifying using Ed25519: {}", str::from_utf8(key).unwrap_or("[raw bytes]"));
                if ed25519::verify(msg, key, sig) {
                    Ok(())
                } else {
                    Err(Error::UptaneVerifySignatures)
                }
            }

            SignatureType::RsaSsaPss => {
                debug!("verifying using RSA SSA-PPS: {}", str::from_utf8(key).unwrap_or("[raw bytes]"));
                let rsa_key = Rsa::public_key_from_pem(&key)?;
                let pub_key = PKey::from_rsa(rsa_key)?;
                let mut verifier = OpensslVerifier::new(MessageDigest::sha256(), &pub_key)?;
                // magic number 6 taken from rsa.h in openssl
                verifier.pkey_ctx_mut().set_rsa_padding(Padding::from_raw(6))?;
                verifier.update(&msg)?;
                if verifier.finish(&sig)? {
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
        let signed = canonicalize_json(signed.as_bytes())?;
        let mut valid_count = 0;
        for sig in &metadata.signatures {
            self.keys.get(&sig.keyid)
                .map(|key| {
                    let ref public = key.keyval.public;
                    // TODO this is a bit ugly
                    (match key.keytype {
                        KeyType::Rsa => SignatureType::RsaSsaPss,
                        KeyType::Ed25519 => SignatureType::Ed25519,
                    })
                    .verify(&signed, public.as_bytes(), sig.sig.as_bytes())
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

    const RSA_2048_PUB: &'static [u8; 450] = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvK19Xh7Y1zzdjDnXotpx\nLBlDc4oahR98I3YyieKAyPmm3l9R9oZl3HHu9OOA/FVF1/QvwNZbgD9ciLyBGVor\nTNPF/2VZmlQmBF6N3BVkmYF9tF0fu8w2MznCQ9bwHE6JR4oLCsb3H/DSpm/GiQ0n\nWwmeNbWJpVpw5x3j8Tsjc7g7+2PO3e9fqh7gxAoPNj1eGwsiSdG9GVTOTBvsbxQH\n4ZT9lkablCIeMxtIdZtLZ1+LffS+f6qaVf7GCjtmIuo4mFD3BisdyHoLnaSxVSGH\nfRVUSouJPa20nP67PZo6EJoWmEOrqDXtoNASuKfS0BzwftRVl6BR3CCpnyyUbq3y\n7wIDAQAB\n-----END PUBLIC KEY-----";

    #[test]
    fn test_rsa_verify() {
        // signed with openssl using the above key
        let msg = b"hello";
        let sig = "BusPdTkDUUG6ISM83snpKt0U8W3cKT8itiTXzJmWLHYBTytwCgW70gTY7z876cj6pELil9nBNC0YIdR4jhy4mu0cEiIIXqN3YWaEzMXAXt+QyjNBzm9POY6y3NF/jvpbZY3wgu5GbOkC6opRPoVARR3K79D9vRIEp6KDLbytqrFuDYd2rSRVfKkbdmt2kCJ17fV6NUWQocseil0kOtKZUI6jz/wt6M3pm5ni1I94Y+mjbwhw6LYEa9qQ++hwg875daaJSkb5jDJ0jkvwb28gsHLjZd1ldX0fuN3alV0RAb91m6klJbxu1ZC1QAfBsK2plkPKH+E4sOhu7NgneHqgFQ==";
        let sig_raw = sig.from_base64().expect("couldn't parse signed from Base64");
        SignatureType::RsaSsaPss.verify(msg, RSA_2048_PUB, &sig_raw).expect("couldn't verify message");

        {
            let mut bad_msg = msg.clone();
            bad_msg[0] = msg[0] ^ 0x01;
            if SignatureType::RsaSsaPss.verify(&bad_msg, RSA_2048_PUB, &sig_raw).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
        {
            let mut bad_sig = sig_raw.clone();
            bad_sig[0] = sig_raw[0] ^ 0x01;
            if SignatureType::RsaSsaPss.verify(msg, RSA_2048_PUB, &bad_sig).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
    }

    #[test]
    fn test_ed25519_verify() {
        let msg = b"hello";
        let sig = "/VniTdrxQlEXcx5QJGHqI7ptGwTq1wBThbfflb8SLRrEE4LQMkd5yBh/PWGvsU7cFNN+PNhFUZY4QwVq9p4MAg";
        let sig_raw = sig.from_base64().expect("couldn't parse signed from Base64");
        SignatureType::Ed25519.verify(msg, &ED25519_PUB.from_base64().unwrap(), &sig_raw).expect("couldn't verify message");

        {
            let mut bad_msg = msg.clone();
            bad_msg[0] = msg[0] ^ 0x01;
            if SignatureType::Ed25519.verify(&bad_msg, ED25519_PUB, &sig_raw).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
        {
            let mut bad_sig = sig_raw.clone();
            bad_sig[0] = sig_raw[0] ^ 0x01;
            if SignatureType::Ed25519.verify(msg, ED25519_PUB, &bad_sig).is_ok() {
                panic!("Expected signature verification to fail");
            };
        }
    }
}
