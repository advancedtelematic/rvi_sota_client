use chrono::{DateTime, NaiveDateTime, UTC};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use time::Duration;

use datatype::{Error, KeyType};


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, Hash, Eq, PartialEq, Debug, Clone)]
pub enum Role {
    Root,
    Targets,
    Snapshot,
    Timestamp
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Root"      => Ok(Role::Root),
            "Snapshot"  => Ok(Role::Snapshot),
            "Targets"   => Ok(Role::Targets),
            "Timestamp" => Ok(Role::Timestamp),
            _           => Err(Error::UptaneInvalidRole)
        }
    }
}

#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
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


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Metadata {
    pub signatures: Vec<Signature>,
    pub signed:     Vec<u8>
}

#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Signature {
    pub keyid:  String,
    pub method: KeyType,
    pub sig:    String,
}

#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SignedMeta {
    pub _type:   Role,
    pub expires: String,
    pub version: u64
}

impl SignedMeta {
    pub fn expired(&self) -> Result<bool, Error> {
        let expiry = NaiveDateTime::parse_from_str(&self.expires, "%FT%TZ")?;
        Ok(DateTime::from_utc(expiry, UTC) < UTC::now())
    }
}


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Key {
    pub keytype: KeyType,
    pub keyval:  KeyValue,
    pub id:      String,
}

#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct KeyValue {
    pub public: Vec<u8>
}


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct FileMeta {
    pub length: u64,
    pub hashes: HashMap<String, Vec<u8>>,
    pub custom: FileMetaCustom
}

#[allow(non_snake_case)]
#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct FileMetaCustom {
    pub ecuIdentifier: String,
    pub uri: String,
}


pub type UptaneKeys   = HashMap<String, Key>;
pub type UptaneRoles  = HashMap<Role, RoleData>;
pub type UptaneMeta   = HashMap<String, FileMeta>;
pub type UptaneCustom = HashMap<String, FileMetaCustom>;


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Root {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub keys:    UptaneKeys,
    pub roles:   UptaneRoles,
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


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Targets {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub targets: UptaneMeta,
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


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Snapshot {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub meta:    UptaneMeta,
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


#[derive(RustcDecodable, RustcEncodable, Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Timestamp {
    pub _type:   Role,
    pub version: u64,
    pub expires: DateTime<UTC>,
    pub meta:    UptaneMeta
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
