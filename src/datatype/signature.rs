use crypto::ed25519;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Rsa, Padding};
use openssl::sign::{Verifier as OpensslVerifier};
use ring::rand::SystemRandom;
use ring::signature::{RSAKeyPair, RSASigningState, RSA_PSS_SHA256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as SerdeError;
use serde_json as json;
use std::io::Write;
use std::os::raw::c_int;
use std::process::{Command, Stdio};
use std::str::{self, FromStr};
use std::sync::Arc;
use untrusted::Input;

use datatype::{Error, KeyType};


const RSA_PKCS1_PSS_PADDING: c_int = 6;


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Signature {
    pub keyid:  String,
    pub method: SignatureType,
    pub sig:    String,
}


#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum SignatureType {
    Ed25519,
    RsaSsaPss,
}

impl Deserialize for SignatureType {
    fn deserialize<D: Deserializer>(de: D) -> Result<Self, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("unknown SignatureType: {}", err)))
        } else {
            Err(SerdeError::custom("unknown SignatureType"))
        }
    }
}

impl Serialize for SignatureType {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(match *self {
            SignatureType::Ed25519   => "ed25519",
            SignatureType::RsaSsaPss => "rsassa-pss"
        })
    }
}

impl FromStr for SignatureType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519"    => Ok(SignatureType::Ed25519),
            "rsassa-pss" => Ok(SignatureType::RsaSsaPss),
            _ => Err(Error::TufSigType(s.to_string()))
        }
    }
}

impl From<KeyType> for SignatureType {
    fn from(keytype: KeyType) -> Self {
        match keytype {
            KeyType::Ed25519 => SignatureType::Ed25519,
            KeyType::Rsa     => SignatureType::RsaSsaPss,
        }
    }
}

impl SignatureType {
    pub fn sign_msg(&self, msg: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            SignatureType::Ed25519 => unimplemented!(),

            SignatureType::RsaSsaPss => {
                Command::new("openssl")
                    .args(&["rsa", "-inform", "PEM", "-outform", "DER"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(Error::Io)
                    .and_then(|mut child| {
                        if let Some(ref mut stdin) = child.stdin {
                            stdin.write_all(key)?;
                            stdin.flush()?;
                        } else {
                            return Err(Error::KeySign("no openssl stdin".into()));
                        }
                        Ok(child.wait_with_output()?)
                    })
                    .and_then(|output| if output.status.success() {
                        let key_pair = RSAKeyPair::from_der(Input::from(&output.stdout))
                            .map_err(|err| Error::KeySign(format!("couldn't read keypair: {}", err)))?;
                        let mut state = RSASigningState::new(Arc::new(key_pair))
                            .map_err(|err| Error::KeySign(format!("couldn't get signing state: {}", err)))?;
                        let mut signature = vec![0; state.key_pair().public_modulus_len()];
                        state.sign(&RSA_PSS_SHA256, &SystemRandom::new(), msg, &mut signature)
                            .map_err(|err| Error::KeySign(format!("couldn't sign state: {}", err)))?;
                        Ok(signature)
                    } else {
                        Err(Error::KeySign("RsaSsaPss signing failed".into()))
                    })
            }
        }
    }

    pub fn verify_msg(&self, msg: &[u8], key: &[u8], sig: &[u8]) -> bool {
        match *self {
            SignatureType::Ed25519 => ed25519::verify(msg, key, sig),
            SignatureType::RsaSsaPss => {
                let outcome = || -> Result<bool, Error> {
                    let pub_key = PKey::from_rsa(Rsa::public_key_from_der(key)?)?;
                    let mut verifier = OpensslVerifier::new(MessageDigest::sha256(), &pub_key)?;
                    verifier.pkey_ctx_mut().set_rsa_padding(Padding::from_raw(RSA_PKCS1_PSS_PADDING))?;
                    verifier.update(msg)?;
                    Ok(verifier.finish(sig)?)
                }();
                outcome.unwrap_or_else(|err| { trace!("RSA SSA-PSS verification failed: {}", err); false })
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use base64;
    use pem;


    #[test]
    fn test_rsa_sign() {
        let priv_key = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdC9QttkMbF5qB\n2plVU2hhG2sieXS2CVc3E8rm/oYGc9EHnlPMcAuaBtn9jaBo37PVYO+VFInzMu9f\nVMLm7d/hQxv4PjTBpkXvw1Ad0Tqhg/R8Lc4SXPxWxlVhg0ahLn3kDFQeEkrTNW7k\nxpAxWiE8V09ETcPwyNhPfcWeiBePwh8ySJ10IzqHt2kXwVbmL4F/mMX07KBYWIcA\n52TQLs2VhZLIaUBv9ZBxymAvogGz28clx7tHOJ8LZ/daiMzmtv5UbXPdt+q55rLJ\nZ1TuG0CuRqhTOllXnIvAYRQr6WBaLkGGbezQO86MDHBsV5TsG6JHPorrr6ogo+Lf\npuH6dcnHAgMBAAECggEBAMC/fs45fzyRkXYn4srHh14d5YbTN9VAQd/SD3zrdn0L\n4rrs8Y90KHmv/cgeBkFMx+iJtYBev4fk41xScf2icTVhKnOF8sTls1hGDIdjmeeb\nQ8ZAvs++a39TRMJaEW2dN8NyiKsMMlkH3+H3z2ZpfE+8pm8eDHza9dwjBP6fF0SP\nV1XPd2OSrJlvrgBrAU/8WWXYSYK+5F28QtJKsTuiwQylIHyJkd8cgZhgYXlUVvTj\nnHFJblpAT0qphji7p8G4Ejg+LNxu/ZD+D3wQ6iIPgKFVdC4uXmPwlf1LeYqXW0+g\ngTmHY7a/y66yn1H4A5gyfx2EffFMQu0Sl1RqzDVYYjECgYEA9Hy2QsP3pxW27yLs\nCu5e8pp3vZpdkNA71+7v2BVvaoaATnsSBOzo3elgRYsN0On4ObtfQXB3eC9poNuK\nzWxj8bkPbVOCpSpq//sUSqkh/XCmAhDl78BkgmWDb4EFEgcAT2xPBTHkb70jVAXB\nE1HBwsBcXhdxzRt8IYiBG+68d/8CgYEA53SJYpJ809lfpAG0CU986FFD7Fi/SvcX\n21TVMn1LpHuH7MZ2QuehS0SWevvspkIUm5uT3PrhTxdohAInNEzsdeHhTU11utIO\nrKnrtgZXKsBG4idsHu5ZQzp4n3CBEpfPFbOtP/UEKI/IGaJWGXVgG4J6LWmQ9LK9\nilNTaOUQ7jkCgYB+YP0B9DTPLN1cLgwf9mokNA7TdrkJA2r7yuo2I5ZtVUt7xghh\nfWk+VMXMDP4+UMNcbGvn8s/+01thqDrOx0m+iO/djn6JDC01Vz98/IKydImLpdqG\nHUiXUwwnFmVdlTrm01DhmZHA5N8fLr5IU0m6dx8IEExmPt/ioaJDoxvPVwKBgC+8\n1H01M3PKWLSN+WEWOO/9muHLaCEBF7WQKKzSNODG7cEDKe8gsR7CFbtl7GhaJr/1\ndajVQdU7Qb5AZ2+dEgQ6Q2rbOBYBLy+jmE8hvaa+o6APe3hhtp1sGObhoG2CTB7w\nwSH42hO3nBDVb6auk9T4s1Rcep5No1Q9XW28GSLZAoGATFlXg1hqNKLO8xXq1Uzi\nkDrN6Ep/wq80hLltYPu3AXQn714DVwNa3qLP04dAYXbs9IaQotAYVVGf6N1IepLM\nfQU6Q9fp9FtQJdU+Mjj2WMJVWbL0ihcU8VZV5TviNvtvR1rkToxSLia7eh39AY5G\nvkgeMZm7SwqZ9c/ZFnjJDqc=\n-----END PRIVATE KEY-----";
        assert!(SignatureType::RsaSsaPss.sign_msg(b"hello", priv_key).is_ok());
    }

    #[test]
    fn test_rsa_verify() {
        let pub_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvK19Xh7Y1zzdjDnXotpx\nLBlDc4oahR98I3YyieKAyPmm3l9R9oZl3HHu9OOA/FVF1/QvwNZbgD9ciLyBGVor\nTNPF/2VZmlQmBF6N3BVkmYF9tF0fu8w2MznCQ9bwHE6JR4oLCsb3H/DSpm/GiQ0n\nWwmeNbWJpVpw5x3j8Tsjc7g7+2PO3e9fqh7gxAoPNj1eGwsiSdG9GVTOTBvsbxQH\n4ZT9lkablCIeMxtIdZtLZ1+LffS+f6qaVf7GCjtmIuo4mFD3BisdyHoLnaSxVSGH\nfRVUSouJPa20nP67PZo6EJoWmEOrqDXtoNASuKfS0BzwftRVl6BR3CCpnyyUbq3y\n7wIDAQAB\n-----END PUBLIC KEY-----";
        let pub_sig = "BusPdTkDUUG6ISM83snpKt0U8W3cKT8itiTXzJmWLHYBTytwCgW70gTY7z876cj6pELil9nBNC0YIdR4jhy4mu0cEiIIXqN3YWaEzMXAXt+QyjNBzm9POY6y3NF/jvpbZY3wgu5GbOkC6opRPoVARR3K79D9vRIEp6KDLbytqrFuDYd2rSRVfKkbdmt2kCJ17fV6NUWQocseil0kOtKZUI6jz/wt6M3pm5ni1I94Y+mjbwhw6LYEa9qQ++hwg875daaJSkb5jDJ0jkvwb28gsHLjZd1ldX0fuN3alV0RAb91m6klJbxu1ZC1QAfBsK2plkPKH+E4sOhu7NgneHqgFQ==";
        let msg = b"hello";
        let key = pem::parse(pub_key).unwrap().contents;
        let sig = base64::decode(pub_sig).unwrap();
        assert!(SignatureType::RsaSsaPss.verify_msg(msg, &key, &sig));

        let mut bad_msg = msg.clone();
        bad_msg[0] = msg[0] ^ 0x01;
        assert_eq!(false, SignatureType::RsaSsaPss.verify_msg(&bad_msg, pub_key.as_bytes(), &sig));

        let mut bad_sig = sig.clone();
        bad_sig[0] = sig[0] ^ 0x01;
        assert_eq!(false, SignatureType::RsaSsaPss.verify_msg(msg, pub_key.as_bytes(), &bad_sig));
    }

    #[test]
    fn test_ed25519_verify() {
        // signing key: 0wm+qYNKH2v7VUMy0lEz0ZfOEtEbdbDNwklW5PPLs4WpCLVDpXuapnO3XZQ9i1wV3aiIxi1b5TxVeVeulbyUyw==
        let pub_key = "qQi1Q6V7mqZzt12UPYtcFd2oiMYtW+U8VXlXrpW8lMs=";
        let pub_sig = "/VniTdrxQlEXcx5QJGHqI7ptGwTq1wBThbfflb8SLRrEE4LQMkd5yBh/PWGvsU7cFNN+PNhFUZY4QwVq9p4MAg";
        let msg = b"hello";
        let key = base64::decode(pub_key).unwrap();
        let sig = base64::decode(pub_sig).unwrap();
        assert!(SignatureType::Ed25519.verify_msg(msg, &key, &sig));

        let mut bad_msg = msg.clone();
        bad_msg[0] = msg[0] ^ 0x01;
        assert_eq!(false, SignatureType::Ed25519.verify_msg(&bad_msg, pub_key.as_bytes(), &sig));

        let mut bad_sig = sig.clone();
        bad_sig[0] = sig[0] ^ 0x01;
        assert_eq!(false, SignatureType::Ed25519.verify_msg(msg, pub_key.as_bytes(), &bad_sig));
    }
}
