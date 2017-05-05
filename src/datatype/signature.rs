use crypto::ed25519;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Rsa, Padding};
use openssl::sign::Verifier;
use ring::rand::SystemRandom;
use ring::signature::{RSAKeyPair, RSASigningState, RSA_PSS_SHA256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as SerdeError;
use serde_json as json;
use std::os::raw::c_int;
use std::str::{self, FromStr};
use std::sync::Arc;
use untrusted::Input;

use datatype::Error;


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

impl<'de> Deserialize<'de> for SignatureType {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
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

impl SignatureType {
    pub fn sign_msg(&self, msg: &[u8], der_key: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            SignatureType::Ed25519 => unimplemented!(),

            SignatureType::RsaSsaPss => {
                let pair = RSAKeyPair::from_der(Input::from(der_key))?;
                let mut state = RSASigningState::new(Arc::new(pair))?;
                let mut sig = vec![0; state.key_pair().public_modulus_len()];
                state.sign(&RSA_PSS_SHA256, &SystemRandom::new(), msg, &mut sig)?;
                Ok(sig)
            }
        }
    }

    pub fn verify_msg(&self, msg: &[u8], der_key: &[u8], sig: &[u8]) -> bool {
        match *self {
            SignatureType::Ed25519 => ed25519::verify(msg, der_key, sig),

            SignatureType::RsaSsaPss => {
                let verify = || -> Result<bool, Error> {
                    let pub_key = PKey::from_rsa(Rsa::public_key_from_der(der_key)?)?;
                    let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_key)?;
                    verifier.pkey_ctx_mut().set_rsa_padding(Padding::from_raw(RSA_PKCS1_PSS_PADDING))?;
                    verifier.update(msg)?;
                    Ok(verifier.finish(sig)?)
                };
                verify().unwrap_or_else(|err| { trace!("RSA SSA-PSS verification failed: {}", err); false })
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use pem;

    use datatype::Util;


    fn test_msg() -> Vec<u8> { "hello".as_bytes().into() }
    fn flip_bit(data: &mut [u8]) -> &[u8] { data[0] ^= 1; data }

    #[test]
    fn test_rsa_sign_and_verify() {
        let priv_key = Util::read_file("tests/keys/rsa.der").expect("read priv");
        let pub_key = pem::parse(Util::read_file("tests/keys/rsa.pub").expect("read pub")).expect("pub_key").contents;
        let mut sig = SignatureType::RsaSsaPss.sign_msg(&test_msg(), &priv_key).expect("sign_msg");
        assert!(SignatureType::RsaSsaPss.verify_msg(&test_msg(), &pub_key, &sig));
        assert_eq!(false, SignatureType::RsaSsaPss.verify_msg(flip_bit(&mut test_msg()), &pub_key, &sig));
        assert_eq!(false, SignatureType::RsaSsaPss.verify_msg(&test_msg(), &pub_key, flip_bit(&mut sig)));
    }

    #[test]
    fn test_ed25519_verify() {
        // priv_key: 0wm+qYNKH2v7VUMy0lEz0ZfOEtEbdbDNwklW5PPLs4WpCLVDpXuapnO3XZQ9i1wV3aiIxi1b5TxVeVeulbyUyw==
        let pub_key = base64::decode("qQi1Q6V7mqZzt12UPYtcFd2oiMYtW+U8VXlXrpW8lMs=").expect("parse key");
        let mut sig = base64::decode("/VniTdrxQlEXcx5QJGHqI7ptGwTq1wBThbfflb8SLRrEE4LQMkd5yBh/PWGvsU7cFNN+PNhFUZY4QwVq9p4MAg").expect("parse sig");
        assert!(SignatureType::Ed25519.verify_msg(&test_msg(), &pub_key, &sig));
        assert_eq!(false, SignatureType::Ed25519.verify_msg(flip_bit(&mut test_msg()), &pub_key, &sig));
        assert_eq!(false, SignatureType::Ed25519.verify_msg(&test_msg(), &pub_key, flip_bit(&mut sig)));
    }
}
