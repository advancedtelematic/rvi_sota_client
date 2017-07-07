use reqwest;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, Read};
use std::result;
use std::str::FromStr;
use toml;
use uuid;


error_chain!{
    foreign_links {
        Http(reqwest::Error);
        Io(io::Error);
        Toml(toml::de::Error);
        Uuid(uuid::ParseError);
    }

    errors {
        Config(s: String) {
            description("config error")
            display("config error: '{}'", s)
        }
    }
}


#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Environment {
    CI,
    QA,
    Production,
}

impl FromStr for Environment {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_ref() {
            "ci" => Ok(Environment::CI),
            "qa" => Ok(Environment::QA),
            "production" => Ok(Environment::Production),
            _ => Err(format!("unknown environment: {}", s).into())
        }
    }
}

impl Display for Environment {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Environment::CI => write!(f, "https://ci-app.atsgarage.com/api/v1"),
            Environment::QA => write!(f, "https://qa-app.atsgarage.com/api/v1"),
            Environment::Production => write!(f, "https://app.atsgarage.com/api/v1"),
        }
    }
}

impl<'de> Deserialize<'de> for Environment {
    fn deserialize<D: Deserializer<'de>>(de: D) -> result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        s.parse().map_err(|err| serde::de::Error::custom(format!("{}", err)))
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateTargets {
    pub targets: HashMap<String, Update>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Update {
    pub from: Option<UpdateTarget>,
    pub to: UpdateTarget
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


pub struct Text;

impl Text {
    pub fn read(path: &str) -> Result<String> {
        let mut file = File::open(path)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
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
