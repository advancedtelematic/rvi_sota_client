use chrono::{DateTime, NaiveDateTime, UTC};
use rustc_serialize::base64::{self, ToBase64};
use serde;
use serde_json as json;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use time::Duration;

use datatype::{Error, SigType, KeyType, canonicalize_json};


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
        let canonical = canonicalize_json(json::to_string(&signed)?.as_bytes())?;
        let sig = sigtype.sign(&canonical, &privkey.der_key)?;
        Ok(TufSigned {
            signatures: vec![Signature {
                keyid:  privkey.keyid.clone(),
                method: sigtype,
                sig:    sig.to_base64(base64::STANDARD)
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
    pub _type:   Role,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, RustcEncodable, RustcDecodable)]
pub struct TufMeta {
    pub length: u64,
    pub hashes: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<TufCustom>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, RustcEncodable, RustcDecodable)]
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
    pub targets: HashMap<String, TufMeta>,
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
    pub meta:    HashMap<String, TufMeta>,
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
    pub meta:    HashMap<String, TufMeta>
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
