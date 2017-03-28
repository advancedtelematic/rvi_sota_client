use base64;
use crypto::ed25519;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Rsa, Padding};
use openssl::sign::{Verifier as OpensslVerifier};
use pem;
use ring::{rand, signature};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as SerdeError;
use serde_json as json;
use std::collections::HashMap;
use std::io::Write;
use std::os::raw::c_int;
use std::process::{Command, Stdio};
use std::str::{self, FromStr};
use std::sync::Arc;
use untrusted;

use datatype::{Error, Key, RoleData, RoleName, RoleMeta, TufSigned, TufRole, canonicalize_json};


const RSA_PKCS1_PSS_PADDING: c_int = 6;


pub struct Verified {
    pub role:    RoleName,
    pub data:    RoleData,
    pub old_ver: u64,
    pub new_ver: u64,
}

impl Verified {
    pub fn is_new(&self) -> bool {
        self.new_ver > self.old_ver
    }
}


#[derive(Default)]
pub struct Verifier {
    keys:     HashMap<String, Key>,
    roles:    HashMap<RoleName, RoleMeta>,
    versions: HashMap<RoleName, u64>,
}

impl Verifier {
    pub fn add_key(&mut self, id: String, key: Key) {
        trace!("inserting to verifier: {}", id);
        self.keys.insert(id, key);
    }

    pub fn add_meta(&mut self, role: RoleName, meta: RoleMeta) {
        trace!("inserting role metadata to verifier: {:?}", meta);
        self.roles.insert(role, meta);
    }

    pub fn set_version(&mut self, role: &RoleName, new_ver: u64) -> u64 {
        let old_ver = self.versions.insert(role.clone(), new_ver).unwrap_or(0);
        if new_ver > old_ver {
            debug!("{} version changed: {} -> {}", role, old_ver, new_ver);
        }
        old_ver
    }

    /// Verify the signed data then return the version.
    pub fn verify(&self, role: &RoleName, signed: &TufSigned) -> Result<u64, Error> {
        self.verify_signatures(role, signed)?;
        let tuf_role = json::from_value::<TufRole>(signed.signed.clone())?;
        if tuf_role._type != *role {
            Err(Error::UptaneInvalidRole)
        } else if tuf_role.expired()? {
            Err(Error::UptaneExpired)
        } else {
            Ok(tuf_role.version)
        }
    }

    pub fn verify_signatures(&self, role: &RoleName, signed: &TufSigned) -> Result<(), Error> {
        if signed.signatures.is_empty() { return Err(Error::UptaneMissingSignatures); }
        let cjson = canonicalize_json(json::to_string(&signed.signed)?.as_bytes())?;

        let mut valid_count = 0;
        for sig in &signed.signatures {
            let _ = self.keys
                .get(&sig.keyid)
                .or_else(|| { debug!("couldn't find key: {}", sig.keyid); None })
                .map(|key| {
                    let public = &key.keyval.public;
                    let pem = pem::parse(public)
                        .map(|pem| pem.contents)
                        .map_err(|err| trace!("couldn't parse public key as pem for {}: {:?}", public, err))?;
                    let sig = base64::decode(&sig.sig)
                        .map_err(|err| trace!("couldn't convert sig from base64 for {}: {}", public, err))?;

                    let sig_type: SigType = key.keytype.clone().into();
                    sig_type.verify(&cjson, &pem, &sig)
                        .map_err(|err| trace!("failed verification for {}: {}", public, err))
                        .map(|_| valid_count += 1)
                        .map(|_| trace!("successful verification with: {}", public))
                });
        }

        trace!("getting role: {}", role);
        let role = self.roles.get(role).ok_or(Error::UptaneUnknownRole)?;
        if valid_count < role.threshold {
            Err(Error::UptaneRoleThreshold)
        } else {
            Ok(())
        }
    }
}


#[derive(Serialize, PartialEq, Eq, Debug, Clone)]
pub enum KeyType {
    Ed25519,
    Rsa,
}

impl Deserialize for KeyType {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("unknown KeyType: {}", err)))
        } else {
            Err(SerdeError::custom("unknown KeyType"))
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


#[derive(PartialEq, Eq, Debug, Clone)]
pub enum SigType {
    Ed25519,
    RsaSsaPss,
}

impl Deserialize for SigType {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("unknown SigType: {}", err)))
        } else {
            Err(SerdeError::custom("unknown SigType"))
        }
    }
}

impl Serialize for SigType {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(match *self {
            SigType::Ed25519   => "ed25519",
            SigType::RsaSsaPss => "rsassa-pss"
        })
    }
}

impl FromStr for SigType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519"    => Ok(SigType::Ed25519),
            "rsassa-pss" => Ok(SigType::RsaSsaPss),
            _ => Err(Error::UptaneInvalidSigType(s.to_string()))
        }
    }
}

impl From<KeyType> for SigType {
    fn from(keytype: KeyType) -> Self {
        match keytype {
            KeyType::Ed25519 => SigType::Ed25519,
            KeyType::Rsa     => SigType::RsaSsaPss,
        }
    }
}

impl SigType {
    pub fn sign(&self, msg: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            SigType::Ed25519 => unimplemented!(),

            SigType::RsaSsaPss => {
                let mut child = Command::new("openssl")
                    .args(&["rsa", "-inform", "PEM", "-outform", "DER"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                {
                    match child.stdin.as_mut() {
                        Some(stdin) => {
                            stdin.write_all(key)?;
                            stdin.flush()?;
                        },
                        None => return Err(Error::Verify("stdin not found".to_string())),
                    }
                }

                let output = child.wait_with_output()?;
                if !output.status.success() {
                    let stdout = str::from_utf8(&output.stdout).unwrap_or("[stdout not utf8]");
                    let stderr = str::from_utf8(&output.stderr).unwrap_or("[stderr not utf8]");
                    return Err(Error::Verify(format!("stdout: {}\nstderr: {}", stdout, stderr)));
                }

                let key_bytes_der = untrusted::Input::from(&output.stdout);
                let key_pair = signature::RSAKeyPair::from_der(key_bytes_der)
                    .map_err(|err| Error::Verify(format!("couldn't read keypair: {}", err)))?;

                let key_pair = Arc::new(key_pair);
                let mut signing_state = signature::RSASigningState::new(key_pair)
                    .map_err(|err| Error::Verify(format!("couldn't get signing state: {}", err)))?;

                let rng = rand::SystemRandom::new();
                let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
                signing_state.sign(&signature::RSA_PSS_SHA256, &rng, msg, &mut signature)
                    .map_err(|err| Error::Verify(format!("couldn't sign state: {}", err)))?;

                Ok(signature)
            }
        }
    }

    pub fn verify(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> Result<(), Error> {
        match *self {
            SigType::Ed25519 => {
                trace!("verifying using Ed25519");
                if ed25519::verify(msg, key, sig) { Ok(()) } else { Err(Error::UptaneVerifySignatures) }
            }

            SigType::RsaSsaPss => {
                trace!("verifying using RSA SSA-PPS");
                let pub_key = PKey::from_rsa(Rsa::public_key_from_der(key)?)?;
                let mut verifier = OpensslVerifier::new(MessageDigest::sha256(), &pub_key)?;
                verifier.pkey_ctx_mut().set_rsa_padding(Padding::from_raw(RSA_PKCS1_PSS_PADDING))?;
                verifier.update(msg)?;
                if verifier.finish(sig)? { Ok(()) } else { Err(Error::UptaneVerifySignatures) }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use base64;
    use pem;

    use super::*;


    // signing key: 0wm+qYNKH2v7VUMy0lEz0ZfOEtEbdbDNwklW5PPLs4WpCLVDpXuapnO3XZQ9i1wV3aiIxi1b5TxVeVeulbyUyw==
    const ED25519_PUB: &'static str = "qQi1Q6V7mqZzt12UPYtcFd2oiMYtW+U8VXlXrpW8lMs=";
    const RSA_2048_PUB: &'static str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvK19Xh7Y1zzdjDnXotpx\nLBlDc4oahR98I3YyieKAyPmm3l9R9oZl3HHu9OOA/FVF1/QvwNZbgD9ciLyBGVor\nTNPF/2VZmlQmBF6N3BVkmYF9tF0fu8w2MznCQ9bwHE6JR4oLCsb3H/DSpm/GiQ0n\nWwmeNbWJpVpw5x3j8Tsjc7g7+2PO3e9fqh7gxAoPNj1eGwsiSdG9GVTOTBvsbxQH\n4ZT9lkablCIeMxtIdZtLZ1+LffS+f6qaVf7GCjtmIuo4mFD3BisdyHoLnaSxVSGH\nfRVUSouJPa20nP67PZo6EJoWmEOrqDXtoNASuKfS0BzwftRVl6BR3CCpnyyUbq3y\n7wIDAQAB\n-----END PUBLIC KEY-----";
    // Note: this key has nothing to do with the above public key
    const RSA_2048_PRIV: &'static [u8; 1703] = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdC9QttkMbF5qB\n2plVU2hhG2sieXS2CVc3E8rm/oYGc9EHnlPMcAuaBtn9jaBo37PVYO+VFInzMu9f\nVMLm7d/hQxv4PjTBpkXvw1Ad0Tqhg/R8Lc4SXPxWxlVhg0ahLn3kDFQeEkrTNW7k\nxpAxWiE8V09ETcPwyNhPfcWeiBePwh8ySJ10IzqHt2kXwVbmL4F/mMX07KBYWIcA\n52TQLs2VhZLIaUBv9ZBxymAvogGz28clx7tHOJ8LZ/daiMzmtv5UbXPdt+q55rLJ\nZ1TuG0CuRqhTOllXnIvAYRQr6WBaLkGGbezQO86MDHBsV5TsG6JHPorrr6ogo+Lf\npuH6dcnHAgMBAAECggEBAMC/fs45fzyRkXYn4srHh14d5YbTN9VAQd/SD3zrdn0L\n4rrs8Y90KHmv/cgeBkFMx+iJtYBev4fk41xScf2icTVhKnOF8sTls1hGDIdjmeeb\nQ8ZAvs++a39TRMJaEW2dN8NyiKsMMlkH3+H3z2ZpfE+8pm8eDHza9dwjBP6fF0SP\nV1XPd2OSrJlvrgBrAU/8WWXYSYK+5F28QtJKsTuiwQylIHyJkd8cgZhgYXlUVvTj\nnHFJblpAT0qphji7p8G4Ejg+LNxu/ZD+D3wQ6iIPgKFVdC4uXmPwlf1LeYqXW0+g\ngTmHY7a/y66yn1H4A5gyfx2EffFMQu0Sl1RqzDVYYjECgYEA9Hy2QsP3pxW27yLs\nCu5e8pp3vZpdkNA71+7v2BVvaoaATnsSBOzo3elgRYsN0On4ObtfQXB3eC9poNuK\nzWxj8bkPbVOCpSpq//sUSqkh/XCmAhDl78BkgmWDb4EFEgcAT2xPBTHkb70jVAXB\nE1HBwsBcXhdxzRt8IYiBG+68d/8CgYEA53SJYpJ809lfpAG0CU986FFD7Fi/SvcX\n21TVMn1LpHuH7MZ2QuehS0SWevvspkIUm5uT3PrhTxdohAInNEzsdeHhTU11utIO\nrKnrtgZXKsBG4idsHu5ZQzp4n3CBEpfPFbOtP/UEKI/IGaJWGXVgG4J6LWmQ9LK9\nilNTaOUQ7jkCgYB+YP0B9DTPLN1cLgwf9mokNA7TdrkJA2r7yuo2I5ZtVUt7xghh\nfWk+VMXMDP4+UMNcbGvn8s/+01thqDrOx0m+iO/djn6JDC01Vz98/IKydImLpdqG\nHUiXUwwnFmVdlTrm01DhmZHA5N8fLr5IU0m6dx8IEExmPt/ioaJDoxvPVwKBgC+8\n1H01M3PKWLSN+WEWOO/9muHLaCEBF7WQKKzSNODG7cEDKe8gsR7CFbtl7GhaJr/1\ndajVQdU7Qb5AZ2+dEgQ6Q2rbOBYBLy+jmE8hvaa+o6APe3hhtp1sGObhoG2CTB7w\nwSH42hO3nBDVb6auk9T4s1Rcep5No1Q9XW28GSLZAoGATFlXg1hqNKLO8xXq1Uzi\nkDrN6Ep/wq80hLltYPu3AXQn714DVwNa3qLP04dAYXbs9IaQotAYVVGf6N1IepLM\nfQU6Q9fp9FtQJdU+Mjj2WMJVWbL0ihcU8VZV5TviNvtvR1rkToxSLia7eh39AY5G\nvkgeMZm7SwqZ9c/ZFnjJDqc=\n-----END PRIVATE KEY-----";


    #[test]
    fn test_rsa_sign() {
        assert!(SigType::RsaSsaPss.sign(b"hello", RSA_2048_PRIV).is_ok());
    }

    #[test]
    fn test_rsa_verify() {
        let msg = b"hello";
        let key = pem::parse(RSA_2048_PUB).unwrap().contents;
        let sig = base64::decode("BusPdTkDUUG6ISM83snpKt0U8W3cKT8itiTXzJmWLHYBTytwCgW70gTY7z876cj6pELil9nBNC0YIdR4jhy4mu0cEiIIXqN3YWaEzMXAXt+QyjNBzm9POY6y3NF/jvpbZY3wgu5GbOkC6opRPoVARR3K79D9vRIEp6KDLbytqrFuDYd2rSRVfKkbdmt2kCJ17fV6NUWQocseil0kOtKZUI6jz/wt6M3pm5ni1I94Y+mjbwhw6LYEa9qQ++hwg875daaJSkb5jDJ0jkvwb28gsHLjZd1ldX0fuN3alV0RAb91m6klJbxu1ZC1QAfBsK2plkPKH+E4sOhu7NgneHqgFQ==").unwrap();
        assert!(SigType::RsaSsaPss.verify(msg, &key, &sig).is_ok());

        let mut bad_msg = msg.clone();
        bad_msg[0] = msg[0] ^ 0x01;
        assert!(SigType::RsaSsaPss.verify(&bad_msg, RSA_2048_PUB.as_bytes(), &sig).is_err());

        let mut bad_sig = sig.clone();
        bad_sig[0] = sig[0] ^ 0x01;
        assert!(SigType::RsaSsaPss.verify(msg, RSA_2048_PUB.as_bytes(), &bad_sig).is_err());
    }

    #[test]
    fn test_ed25519_verify() {
        let msg = b"hello";
        let key = base64::decode(ED25519_PUB).unwrap();
        let sig = base64::decode("/VniTdrxQlEXcx5QJGHqI7ptGwTq1wBThbfflb8SLRrEE4LQMkd5yBh/PWGvsU7cFNN+PNhFUZY4QwVq9p4MAg").unwrap();
        assert!(SigType::Ed25519.verify(msg, &key, &sig).is_ok());

        let mut bad_msg = msg.clone();
        bad_msg[0] = msg[0] ^ 0x01;
        assert!(SigType::Ed25519.verify(&bad_msg, ED25519_PUB.as_bytes(), &sig).is_err());

        let mut bad_sig = sig.clone();
        bad_sig[0] = sig[0] ^ 0x01;
        assert!(SigType::Ed25519.verify(msg, ED25519_PUB.as_bytes(), &bad_sig).is_err());
    }
}
