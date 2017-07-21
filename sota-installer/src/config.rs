use serde::{self, Deserialize, Deserializer};
use std::str::FromStr;
use std::time::Duration;
use toml;

use installer::{Installer, InstallType};
use sota::atomic::{Multicast, Secondary};
use sota::datatype::{Error, PrivateKey, SignatureType, SocketAddrV4, Util};


pub struct App {
    pub install_type: InstallType,
    pub oneshot: bool,
    pub config: Config,
}

impl App {
    pub fn into_secondary(self) -> Result<Secondary, Error> {
        let bus = match self.config.bus_type {
            Some(BusType::Udp) | None => {
                let udp = Udp::default();
                Multicast::new(udp.wake_up.0, udp.message.0)
            }
        }?;

        let step = Installer {
            install_type: self.install_type,

            serial: self.config.serial.clone(),
            private_key: PrivateKey {
                keyid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
                der_key: Util::read_file(&self.config.private_key_path)?
            },
            sig_type: self.config.signature_type.unwrap_or(SignatureType::RsaSsaPss),

            image_dir: self.config.image_dir.unwrap_or_else(|| "/tmp/sota-writer-images".into()),
            filepath: None,
        };

        let timeout = Duration::from_secs(self.config.timeout.unwrap_or(60));
        Ok(Secondary::new(self.config.serial, Box::new(bus), Box::new(step), timeout, None))
    }
}


#[derive(Deserialize)]
pub struct Config {
    pub serial: String,
    pub private_key_path: String,
    pub signature_type: Option<SignatureType>,

    pub timeout: Option<u64>,
    pub bus_type: Option<BusType>,
    pub image_dir: Option<String>,
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(toml::from_str(s)?)
    }
}


#[derive(PartialEq, Clone, Copy, Debug)]
pub enum BusType {
    Udp
}

impl FromStr for BusType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_ref() {
            "udp" => Ok(BusType::Udp),
            _ => Err(Error::Parse(format!("unknown bus_type: {}", s)))
        }
    }
}

impl<'de> Deserialize<'de> for BusType {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        s.parse().map_err(|err| serde::de::Error::custom(format!("{}", err)))
    }
}


#[derive(Deserialize)]
pub struct Udp {
    pub wake_up: SocketAddrV4,
    pub message: SocketAddrV4,
}

impl Default for Udp {
    fn default() -> Self {
        Udp {
            wake_up: "232.0.0.011:23211".parse().expect("parse udp.wake_up"),
            message: "232.0.0.011:23212".parse().expect("parse udp.message"),
        }
    }
}
