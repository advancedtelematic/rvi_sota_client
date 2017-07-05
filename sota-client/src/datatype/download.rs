use std::fmt::{self, Display, Formatter};
use uuid::Uuid;


/// Details of a package for downloading.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct Package {
    pub name:    String,
    pub version: String
}

impl Display for Package {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}", self.name, self.version)
    }
}


/// A request for the device to install a new update.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
#[allow(non_snake_case)]
pub struct UpdateRequest {
    pub requestId:  Uuid,
    pub status:     RequestStatus,
    pub packageId:  Package,
    pub installPos: i32,
    pub createdAt:  String,
}

/// The current status of an `UpdateRequest`.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub enum RequestStatus {
    Pending,
    InFlight,
    Canceled,
    Failed,
    Finished
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

/// A notification to an external package manager that the package was downloaded.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct DownloadComplete {
    pub update_id:    Uuid,
    pub update_image: String,
    pub signature:    String
}

/// A notification to an external package manager that the package download failed.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct DownloadFailed {
    pub update_id: Uuid,
    pub reason:    String
}
