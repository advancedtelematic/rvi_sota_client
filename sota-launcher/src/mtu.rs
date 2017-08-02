use reqwest::header::Headers;
use reqwest::Client;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::result;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::str::FromStr;
use uuid::Uuid;

use config::*;


pub struct MultiTargetUpdate {
    client: Client,
    env: Environment,
    session: PlaySession,
}

impl MultiTargetUpdate {
    pub fn new(env: Environment, session: PlaySession) -> Result<Self> {
        Ok(MultiTargetUpdate {
            client: Client::new()?,
            env: env,
            session: session,
        })
    }

    pub fn create(&self, targets: &UpdateTargets) -> Result<Uuid> {
        let mut resp = self.client
            .post(&format!("{}/multi_target_updates", self.env))
            .json(targets)
            .headers(self.headers())
            .send()?;

        let mut body = String::new();
        resp.read_to_string(&mut body)?;
        debug!("create mtu response: {}", body);
        let uuid = body.trim_matches('"').parse::<Uuid>()?;
        Ok(uuid)
    }

    pub fn launch(&self, device_id: Uuid, update_id: Uuid) -> Result<()> {
        let mut resp = self.client
            .put(&format!("{}/admin/devices/{}/multi_target_update/{}", self.env, device_id, update_id))
            .headers(self.headers())
            .send()?;

        let mut body = String::new();
        resp.read_to_string(&mut body)?;
        debug!("launch response: {}", body);
        Ok(())
    }

    fn headers(&self) -> Headers {
        let mut headers = Headers::new();
        headers.set_raw("Cookie", vec![self.session.into_bytes()]);
        headers.set_raw("Csrf-Token", vec![self.session.csrf_token.as_bytes().to_vec()]);
        headers
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateTargets {
    pub targets: HashMap<String, Update>,
}

impl UpdateTargets {
    pub fn from(targets: &[Target], format: TargetFormat, generate_diff: bool) -> Self {
        UpdateTargets {
            targets: targets.into_iter().map(|target| {
                let update = Update {
                    from: None,
                    to: UpdateTarget {
                        target: target.target.clone(),
                        length: target.length,
                        checksum: Checksum { method: target.method, hash: target.hash.clone() }
                    },
                    format: format,
                    generate_diff: generate_diff,
                };
                (target.hw_id.clone(), update)
            }).collect::<HashMap<String, Update>>()
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetFormat {
    Binary,
    Ostree,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Update {
    pub from: Option<UpdateTarget>,
    pub to: UpdateTarget,
    #[serde(rename = "targetFormat")]
    pub format: TargetFormat,
    #[serde(rename = "generateDiff")]
    pub generate_diff: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateTarget {
    pub target: String,
    #[serde(rename = "targetLength")]
    pub length: u64,
    pub checksum: Checksum,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Checksum {
    pub method: ChecksumMethod,
    pub hash: String,
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum ChecksumMethod {
    Sha256,
    Sha512,
}

impl FromStr for ChecksumMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_ref() {
            "sha256" => Ok(ChecksumMethod::Sha256),
            "sha512" => Ok(ChecksumMethod::Sha512),
            _ => Err(format!("unknown checksum method: {}", s).into())
        }
    }
}

impl Serialize for ChecksumMethod {
    fn serialize<S: Serializer>(&self, ser: S) -> result::Result<S::Ok, S::Error> {
        ser.serialize_str(match *self {
            ChecksumMethod::Sha256 => "sha256",
            ChecksumMethod::Sha512 => "sha512",
        })
    }
}

impl<'de> Deserialize<'de> for ChecksumMethod {
    fn deserialize<D: Deserializer<'de>>(de: D) -> result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        s.parse().map_err(|err| serde::de::Error::custom(format!("{}", err)))
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct PlaySession {
    session: String,
    access_token: String,
    auth_plus_token: String,
    pub csrf_token: String,
    namespace: String,
}

impl FromStr for PlaySession {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let cookie = s.trim().splitn(2, '=').collect::<Vec<_>>();
        if cookie[0] != "PLAY_SESSION" {
            return Err((format!("expected 'PLAY_SESSION=' cookie, got '{}'", cookie[0])).into())
        }

        let parts = cookie[1].split('&').collect::<Vec<_>>();
        let session = parts[0];
        let access_token = parts[1].split('=').collect::<Vec<_>>();
        let auth_plus_token = parts[2].split('=').collect::<Vec<_>>();
        let csrf_token = parts[3].split('=').collect::<Vec<_>>();
        let namespace = parts[4].split('=').collect::<Vec<_>>();

        if access_token[0] != "access_token" {
            return Err(format!("expected key 'access_token', got '{}'", access_token[0]).into())
        } else if auth_plus_token[0] != "auth_plus_access_token" {
            return Err(format!("expected key 'auth_plus_access_token', got '{}'", auth_plus_token[0]).into())
        } else if csrf_token[0] != "csrfToken" {
            return Err(format!("expected key 'csrfToken', got '{}'", csrf_token[0]).into())
        } else if namespace[0] != "namespace" {
            return Err(format!("expected key 'namespace', got '{}'", namespace[0]).into())
        }

        Ok(PlaySession {
            session: session.into(),
            access_token: access_token[1].into(),
            auth_plus_token: auth_plus_token[1].into(),
            csrf_token: csrf_token[1].into(),
            namespace: namespace[1].into(),
        })
    }
}

impl Display for PlaySession {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PLAY_SESSION={}&access_token={}&auth_plus_access_token={}&csrfToken={}&namespace={}",
               self.session, self.access_token, self.auth_plus_token, self.csrf_token, self.namespace)
    }
}

impl<'de> Deserialize<'de> for PlaySession {
    fn deserialize<D: Deserializer<'de>>(de: D) -> result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        s.parse().map_err(|err| serde::de::Error::custom(format!("{}", err)))
    }
}

impl PlaySession {
    pub fn into_bytes(&self) -> Vec<u8> {
        format!("{}", self).as_bytes().to_vec()
    }
}


#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;


    const SESSION: &'static str = "\n\t PLAY_SESSION=1234567890abcdef1234567890abcdef12345678-id_token=1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABC.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG&access_token=abcdefghijklmnop&auth_plus_access_token=1234567890abcdefghijklmnopqrstuvwxy.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG&csrfToken=1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678&namespace=auth0%7C1234567890abcdefghijklmn";

    #[test]
    fn parse_session() {
        let session = SESSION.parse::<PlaySession>().expect("parse");
        assert_eq!(&session.session, "1234567890abcdef1234567890abcdef12345678-id_token=1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABC.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG");
        assert_eq!(&session.access_token, "abcdefghijklmnop");
        assert_eq!(&session.auth_plus_token, "1234567890abcdefghijklmnopqrstuvwxy.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG");
        assert_eq!(&session.csrf_token, "1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678");
        assert_eq!(&session.namespace, "auth0%7C1234567890abcdefghijklmn");
        assert_eq!(format!("{}", session), SESSION.trim());
    }
}
