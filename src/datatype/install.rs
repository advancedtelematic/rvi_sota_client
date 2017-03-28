use serde::{Serialize, Serializer};
use std::str::FromStr;

use datatype::Error;


/// The installation outcome from a package manager.
pub struct InstallOutcome {
    code:   InstallCode,
    stdout: String,
    stderr: String,
}

impl InstallOutcome {
    /// Create a new installation outcome.
    pub fn new(code: InstallCode, stdout: String, stderr: String) -> InstallOutcome {
        InstallOutcome { code: code, stdout: stdout, stderr: stderr }
    }

    /// Convert an `InstallOutcome` into a `InstallResult
    pub fn into_result(self, id: String) -> InstallResult {
        InstallResult::new(id, self.code, format!("stdout: {}\nstderr: {}\n", self.stdout, self.stderr))
    }
}


/// An encodable response of the installation outcome.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InstallResult {
    pub id:          String,
    pub result_code: InstallCode,
    pub result_text: String,
}

impl InstallResult {
    /// Create a new installation result.
    pub fn new(id: String, code: InstallCode, text: String) -> InstallResult {
        InstallResult { id: id, result_code: code, result_text: text }
    }

    /// Convert a single installation result to an `InstallReport`.
    pub fn into_report(self) -> InstallReport {
        InstallReport { update_id: self.id.clone(), operation_results: vec![self] }
    }
}


/// A report of a list of installation results.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InstallReport {
    pub update_id:         String,
    pub operation_results: Vec<InstallResult>
}

impl InstallReport {
    /// Create a new report from a list of installation results.
    pub fn new(update_id: String, results: Vec<InstallResult>) -> Self {
        InstallReport { update_id: update_id, operation_results: results }
    }
}


/// Enumerate the possible outcomes when trying to install a package.
#[allow(non_camel_case_types)]
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum InstallCode {
    /// Operation executed successfully
    OK = 0,
    /// Operation has already been processed
    ALREADY_PROCESSED,
    /// Dependency failure during package install, upgrade, or removal
    DEPENDENCY_FAILURE,
    /// Update image integrity has been compromised
    VALIDATION_FAILED,
    /// Package installation failed
    INSTALL_FAILED,
    /// Package upgrade failed
    UPGRADE_FAILED,
    /// Package removal failed
    REMOVAL_FAILED,
    /// The module loader could not flash its managed module
    FLASH_FAILED,
    /// Partition creation failed
    CREATE_PARTITION_FAILED,
    /// Partition deletion failed
    DELETE_PARTITION_FAILED,
    /// Partition resize failed
    RESIZE_PARTITION_FAILED,
    /// Partition write failed
    WRITE_PARTITION_FAILED,
    /// Partition patching failed
    PATCH_PARTITION_FAILED,
    /// User declined the update
    USER_DECLINED,
    /// Software was blacklisted
    SOFTWARE_BLACKLISTED,
    /// Ran out of disk space
    DISK_FULL,
    /// Software package not found
    NOT_FOUND,
    /// Tried to downgrade to older version
    OLD_VERSION,
    /// SWM Internal integrity error
    INTERNAL_ERROR,
    /// Other error
    GENERAL_ERROR,
}

impl InstallCode {
    /// Was the installation successful?
    pub fn is_success(&self) -> bool {
        match *self {
            InstallCode::OK | InstallCode::ALREADY_PROCESSED => true,
            _ => false
        }
    }
}

impl Default for InstallCode {
    fn default() -> Self {
        InstallCode::OK
    }
}

impl FromStr for InstallCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<InstallCode, Error> {
        match &*s.to_uppercase() {
            "0"  | "OK"                      => Ok(InstallCode::OK),
            "1"  | "ALREADY_PROCESSED"       => Ok(InstallCode::ALREADY_PROCESSED),
            "2"  | "DEPENDENCY_FAILURE"      => Ok(InstallCode::DEPENDENCY_FAILURE),
            "3"  | "VALIDATION_FAILED"       => Ok(InstallCode::VALIDATION_FAILED),
            "4"  | "INSTALL_FAILED"          => Ok(InstallCode::INSTALL_FAILED),
            "5"  | "UPGRADE_FAILED"          => Ok(InstallCode::UPGRADE_FAILED),
            "6"  | "REMOVAL_FAILED"          => Ok(InstallCode::REMOVAL_FAILED),
            "7"  | "FLASH_FAILED"            => Ok(InstallCode::FLASH_FAILED),
            "8"  | "CREATE_PARTITION_FAILED" => Ok(InstallCode::CREATE_PARTITION_FAILED),
            "9"  | "DELETE_PARTITION_FAILED" => Ok(InstallCode::DELETE_PARTITION_FAILED),
            "10" | "RESIZE_PARTITION_FAILED" => Ok(InstallCode::RESIZE_PARTITION_FAILED),
            "11" | "WRITE_PARTITION_FAILED"  => Ok(InstallCode::WRITE_PARTITION_FAILED),
            "12" | "PATCH_PARTITION_FAILED"  => Ok(InstallCode::PATCH_PARTITION_FAILED),
            "13" | "USER_DECLINED"           => Ok(InstallCode::USER_DECLINED),
            "14" | "SOFTWARE_BLACKLISTED"    => Ok(InstallCode::SOFTWARE_BLACKLISTED),
            "15" | "DISK_FULL"               => Ok(InstallCode::DISK_FULL),
            "16" | "NOT_FOUND"               => Ok(InstallCode::NOT_FOUND),
            "17" | "OLD_VERSION"             => Ok(InstallCode::OLD_VERSION),
            "18" | "INTERNAL_ERROR"          => Ok(InstallCode::INTERNAL_ERROR),
            "19" | "GENERAL_ERROR"           => Ok(InstallCode::GENERAL_ERROR),
            _ => Err(Error::Parse(format!("unknown InstallCode: {}", s)))
        }
    }
}

impl Serialize for InstallCode {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u64(self.clone() as u64)
    }
}


/// Encapsulates a single firmware installed on the device.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct InstalledFirmware {
    pub module:        String,
    pub firmware_id:   String,
    pub last_modified: u64
}

/// Encapsulates a single package installed on the device.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct InstalledPackage {
    pub package_id:    String,
    pub name:          String,
    pub description:   String,
    pub last_modified: u64
}

/// An encodable list of packages and firmwares to send to RVI.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InstalledSoftware {
    pub packages:  Vec<InstalledPackage>,
    pub firmwares: Vec<InstalledFirmware>
}

impl InstalledSoftware {
    /// Instantiate a new list of the software installed on the device.
    pub fn new(packages: Vec<InstalledPackage>, firmwares: Vec<InstalledFirmware>) -> InstalledSoftware {
        InstalledSoftware { packages: packages, firmwares: firmwares }
    }
}
