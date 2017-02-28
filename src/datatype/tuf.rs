use chrono::{DateTime, NaiveDateTime, UTC};
use serde;
use serde_json as json;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use time::Duration;

use datatype::{Error, KeyType};


pub type UptaneCustom = HashMap<String, SignedCustom>;


#[derive(Serialize, Hash, Eq, PartialEq, Debug, Clone)]
#[serde(tag = "_type")]
pub enum Role {
    Root,
    Targets,
    Snapshot,
    Timestamp
}

impl serde::Deserialize for Role {
    fn deserialize<D: serde::Deserializer>(de: D) -> Result<Role, D::Error> {
        if let json::Value::String(ref s) = serde::Deserialize::deserialize(de)? {
            s.parse().map_err(|err| serde::de::Error::custom(format!("unknown Role: {}", err)))
        } else {
            Err(serde::de::Error::custom("Unknown `Role` from `_type` field"))
        }
    }
}


impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root"      | "Root"      => Ok(Role::Root),
            "snapshot"  | "Snapshot"  => Ok(Role::Snapshot),
            "targets"   | "Targets"   => Ok(Role::Targets),
            "timestamp" | "Timestamp" => Ok(Role::Timestamp),
            _ => Err(Error::UptaneInvalidRole)
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct RoleData {
    pub keyids:    HashSet<String>,
    pub threshold: u64,
}

impl RoleData {
    pub fn new(keyids: HashSet<String>, threshold: u64) -> Self {
        RoleData { keyids: keyids, threshold: threshold }
    }

    pub fn valid_key(&self, id: &str) -> bool {
        self.keyids.contains(id)
    }
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Key {
    pub keytype: KeyType,
    pub keyval:  KeyValue,
    pub id:      Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct KeyValue {
    pub public: String
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Metadata {
    pub signatures: Vec<Signature>,
    pub signed:     json::Value
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Signature {
    pub keyid:  String,
    pub method: KeyType,
    pub sig:    String,
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Signed {
    pub _type:   Role,
    pub expires: String,
    pub version: u64
}

impl Signed {
    pub fn expired(&self) -> Result<bool, Error> {
        let expiry = NaiveDateTime::parse_from_str(&self.expires, "%FT%TZ")?;
        Ok(DateTime::from_utc(expiry, UTC) < UTC::now())
    }
}


#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, RustcEncodable, RustcDecodable)]
pub struct SignedMeta {
    pub length: u64,
    pub hashes: HashMap<String, String>,
    pub custom: Option<SignedCustom>
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, RustcEncodable, RustcDecodable)]
pub struct SignedCustom {
    pub ecuIdentifier: String,
    pub uri: Option<String>,
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SignedManifest {
    pub vin:                  String,
    pub primary_ecu_serial:   String,
    pub ecu_version_manifest: json::Value
}

impl SignedManifest {
    pub fn from(vin: String, primary_serial: String, version: SignedVersion) -> Self {
        unimplemented!()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SignedVersion {
    pub timeserver_time:          String,
    pub installed_image:          SignedImage,
    pub previous_timeserver_time: String,
    pub ecu_serial:               String,
    pub attacks_detected:         String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct SignedImage {
    pub filepath: String,
    pub fileinfo: SignedMeta
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Root {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub keys:    HashMap<String, Key>,
    pub roles:   HashMap<Role, RoleData>,
    pub consistent_snapshot: bool
}

impl Default for Root {
    fn default() -> Self {
        Root {
            _type:   Role::Root,
            version: 0,
            expires: UTC::now() + Duration::days(365),
            keys:    HashMap::new(),
            roles:   HashMap::new(),
            consistent_snapshot: true
        }
    }
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Targets {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub targets: HashMap<String, SignedMeta>,
}

impl Default for Targets {
    fn default() -> Self {
        Targets {
            _type:   Role::Targets,
            version: 0,
            expires: UTC::now() + Duration::days(30),
            targets: HashMap::new()
        }
    }
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Snapshot {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub meta:    HashMap<String, SignedMeta>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            _type:   Role::Snapshot,
            version: 0,
            expires: UTC::now() + Duration::days(7),
            meta:    HashMap::new()
        }
    }
}


#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Timestamp {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub meta:    HashMap<String, SignedMeta>
}

impl Default for Timestamp {
    fn default() -> Self {
        Timestamp {
            _type:   Role::Timestamp,
            version: 0,
            expires: UTC::now() + Duration::days(1),
            meta:    HashMap::new()
        }
    }
}
