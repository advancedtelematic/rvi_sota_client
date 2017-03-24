use std::fmt::{Display, Formatter, Result as FmtResult};

use rvi::LocalServices;


/// Encapsulate a `String` type as the id of a specific update request.
pub type UpdateRequestId = String;

/// A device update request from Core to be installed by the client.
#[allow(non_snake_case)]
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct UpdateRequest {
    pub requestId:  UpdateRequestId,
    pub status:     UpdateRequestStatus,
    pub packageId:  Package,
    pub installPos: i32,
    pub createdAt:  String,
}

/// The status of an `UpdateRequest` from Core.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub enum UpdateRequestStatus {
    Pending,
    InFlight,
    Canceled,
    Failed,
    Finished
}


/// Encodes the name and version of a specific package.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct Package {
    pub name:    String,
    pub version: String
}

impl Display for Package {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{} {}", self.name, self.version)
    }
}


/// A notification from RVI that a new update is available.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct UpdateAvailable {
    pub update_id:            String,
    pub signature:            String,
    pub description:          String,
    pub request_confirmation: bool,
    pub size:                 u64
}

/// A JSON-RPC request type to notify RVI that a new package download has started.
#[derive(Deserialize, Serialize)]
pub struct DownloadStarted {
    pub device:    String,
    pub update_id: UpdateRequestId,
    pub services:  LocalServices,
}

/// A JSON-RPC request type to notify RVI that a new package chunk was received.
#[derive(Deserialize, Serialize)]
pub struct ChunkReceived {
    pub device:    String,
    pub update_id: UpdateRequestId,
    pub chunks:    Vec<u64>,
}

/// A notification to an external package manager that the package was downloaded.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct DownloadComplete {
    pub update_id:    String,
    pub update_image: String,
    pub signature:    String
}

/// A notification to an external package manager that the package download failed.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct DownloadFailed {
    pub update_id: String,
    pub reason:    String
}
