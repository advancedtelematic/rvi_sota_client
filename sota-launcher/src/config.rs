use json;
use reqwest;
use serde::{self, Deserialize, Deserializer};
use std::{io, result};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use toml;
use uuid::{self, Uuid};

use mtu::*;
use sota;


error_chain!{
    foreign_links {
        Http(reqwest::Error);
        Io(io::Error);
        Json(json::Error);
        Sota(sota::datatype::Error);
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


pub enum App {
    GenerateManifests {
        priv_keys_dir: String
    },

    MultiTargetUpdate {
        env: Environment,
        session: PlaySession,
        targets: Targets,
    },
}


#[derive(PartialEq, Clone, Copy, Debug)]
pub enum Mode {
    Manifests,
    Mtu,
}

impl FromStr for Mode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_ref() {
            "manifests" => Ok(Mode::Manifests),
            "mtu" => Ok(Mode::Mtu),
            _ => Err(format!("unknown mode: {}", s).into())
        }
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D: Deserializer<'de>>(de: D) -> result::Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        s.parse().map_err(|err| serde::de::Error::custom(format!("{}", err)))
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


#[derive(Deserialize)]
pub struct Targets {
    pub device: Device,
    pub targets: Vec<Target>,
}

impl FromStr for Targets {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}

#[derive(Deserialize)]
pub struct Device {
    pub device_id: Uuid,
}

impl FromStr for Device {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}

#[derive(Deserialize)]
pub struct Target {
    pub hw_id: String,
    pub target: String,
    pub length: u64,
    pub method: ChecksumMethod,
    pub hash: String,
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use sota::datatype::Util;


    #[test]
    fn parse_targets() {
        let toml = Util::read_text("examples/targets.toml").expect("read examples/targets.toml");
        let targets = toml.parse::<Targets>().expect("parse targets.toml");
        assert_eq!(targets.device.device_id, "00000000-0000-0000-0000-000000000000".parse::<Uuid>().expect("uuid"));
        assert_eq!(targets.targets.len(), 2);
        assert_eq!(targets.targets[0].method, ChecksumMethod::Sha256);
        assert_eq!(&targets.targets[1].hw_id, "group2");
    }
}
