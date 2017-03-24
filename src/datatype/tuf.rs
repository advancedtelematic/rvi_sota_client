use base64;
use chrono::{DateTime, NaiveDateTime, UTC};
use serde::de::{Deserialize, Deserializer, Error as SerdeError};
use serde_json as json;
use std::fmt::{self, Display, Formatter};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use datatype::{Error, KeyType, OperationResult, SigType, canonicalize_json};


#[derive(Serialize, Hash, Eq, PartialEq, Debug, Clone)]
#[serde(tag = "_type")]
pub enum RoleName {
    Root,
    Targets,
    Snapshot,
    Timestamp
}

impl FromStr for RoleName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root"      | "Root"      => Ok(RoleName::Root),
            "snapshot"  | "Snapshot"  => Ok(RoleName::Snapshot),
            "targets"   | "Targets"   => Ok(RoleName::Targets),
            "timestamp" | "Timestamp" => Ok(RoleName::Timestamp),
            _                         => Err(Error::UptaneInvalidRole)
        }
    }
}

impl Display for RoleName {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            RoleName::Root      => write!(f, "{}", "root"),
            RoleName::Targets   => write!(f, "{}", "targets"),
            RoleName::Snapshot  => write!(f, "{}", "snapshot"),
            RoleName::Timestamp => write!(f, "{}", "timestamp"),
        }
    }
}

impl Deserialize for RoleName {
    fn deserialize<D: Deserializer>(de: D) -> Result<RoleName, D::Error> {
        if let json::Value::String(ref s) = Deserialize::deserialize(de)? {
            s.parse().map_err(|err| SerdeError::custom(format!("unknown RoleName: {}", err)))
        } else {
            Err(SerdeError::custom("Unknown `RoleName` from `_type` field"))
        }
    }
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RoleData {
    pub _type:   RoleName,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub keys:    Option<HashMap<String, Key>>,        // root only
    pub roles:   Option<HashMap<RoleName, RoleMeta>>, // root only
    pub targets: Option<HashMap<String, TufMeta>>,    // targets only
    pub meta:    Option<HashMap<String, TufMeta>>,    // timestamp/snapshot only
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RoleMeta {
    pub keyids:    HashSet<String>,
    pub threshold: u64,
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Key {
    pub keytype: KeyType,
    pub keyval:  KeyValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct KeyValue {
    pub public: String,
}

pub struct PrivateKey {
    pub keyid:   String,
    pub der_key: Vec<u8>,
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct TufSigned {
    pub signatures: Vec<Signature>,
    pub signed:     json::Value,
}

impl TufSigned {
    pub fn sign(signed: json::Value, privkey: &PrivateKey, sigtype: SigType) -> Result<TufSigned, Error> {
        let sig = sigtype.sign(&canonicalize_json(&json::to_vec(&signed)?)?, &privkey.der_key)?;
        Ok(TufSigned {
            signatures: vec![Signature {
                keyid:  privkey.keyid.clone(),
                method: sigtype,
                sig:    base64::encode(&sig),
            }],
            signed: signed,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Signature {
    pub keyid:  String,
    pub method: SigType,
    pub sig:    String,
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct TufRole {
    pub _type:   RoleName,
    pub expires: String,
    pub version: u64,
}

impl TufRole {
    pub fn expired(&self) -> Result<bool, Error> {
        let expiry = NaiveDateTime::parse_from_str(&self.expires, "%FT%TZ")?;
        Ok(DateTime::from_utc(expiry, UTC) < UTC::now())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct TufImage {
    pub filepath: String,
    pub fileinfo: TufMeta
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TufMeta {
    pub length: u64,
    pub hashes: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<TufCustom>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TufCustom {
    pub ecuIdentifier: String,
    pub uri: Option<String>,
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct EcuManifests {
    pub primary_ecu_serial:   String,
    pub ecu_version_manifest: Vec<TufSigned>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct EcuVersion {
    pub attacks_detected:         String,
    pub ecu_serial:               String,
    pub installed_image:          TufImage,
    pub previous_timeserver_time: String,
    pub timeserver_time:          String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<EcuCustom>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct EcuCustom {
    pub operation_result: OperationResult
}
