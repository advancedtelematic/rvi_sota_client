use serde::{self, Deserialize, Deserializer};
use std::str::FromStr;
use std::time::Duration;
use toml;

use installer::{Installer, InstallType};
use sota::atomic::{Multicast, Secondary};
use sota::datatype::{Error, PrivateKey, SignatureType, SocketAddrV4, Util};


#[derive(Deserialize)]
pub struct Config {
    pub ecu: Ecu,
    pub transaction: Option<Transaction>,
    pub udp: Option<Udp>,
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(toml::from_str(s)?)
    }
}

impl Config {
    pub fn to_secondary(&self) -> Result<Secondary, Error> {
        let bus = match self.ecu.bus_type {
            BusType::Udp => {
                if let Some(ref udp) = self.udp {
                    Multicast::new(udp.wake_up.0, udp.message.0)
                } else {
                    Err(Error::Config("UDP bus_type expects [udp] config section".into()))
                }
            }
        }?;

        let step = Installer {
            serial: self.ecu.serial.clone(),
            install_type: self.ecu.install_type,

            private_key: PrivateKey {
                keyid: self.ecu.private_key_id.clone(),
                der_key: Util::read_file(&self.ecu.private_key_path)?
            },
            sig_type: self.ecu.signature_type,
        };

        let timeout = Duration::from_secs(self.transaction.as_ref().and_then(|t| t.timeout).unwrap_or(60));
        let recover = self.transaction.as_ref().and_then(|t| t.recover.clone());
        Ok(Secondary::new(self.ecu.serial.clone(), Box::new(bus), Box::new(step), timeout, recover))
    }
}

#[derive(Deserialize)]
pub struct Ecu {
    pub serial: String,
    pub install_type: InstallType,
    pub bus_type: BusType,

    pub private_key_id: String,
    pub private_key_path: String,
    pub signature_type: SignatureType,
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
pub struct Transaction {
    pub timeout: Option<u64>,
    pub recover: Option<String>,
}


#[derive(Deserialize)]
pub struct Udp {
    pub wake_up: SocketAddrV4,
    pub message: SocketAddrV4,
}
