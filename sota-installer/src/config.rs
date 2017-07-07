use serde::{self, Deserialize, Deserializer};
use std::str::FromStr;
use toml;

use sota::datatype::{Error, SocketAddrV4};


#[derive(Deserialize)]
pub struct Secondary {
    pub ecu: Ecu,
    pub udp: Option<Udp>,
}

impl FromStr for Secondary {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(toml::from_str(s)?)
    }
}


#[derive(Deserialize)]
pub struct Ecu {
    pub serial: String,
    pub bus_type: BusType,
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
