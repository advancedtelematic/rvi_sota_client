use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use uuid::Uuid;

use datatype::{DownloadComplete, InstallReport, InstallResult, Manifests, OstreePackage,
               Package, TufMeta, UpdateAvailable, UpdateRequest};
use uptane::Verified;


/// System-wide events that are broadcast to all interested parties.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Event {
    /// Authentication was successful.
    Authenticated,
    /// An operation failed because we are not currently authenticated.
    NotAuthenticated,
    /// General error event with a printable representation for debugging.
    Error(String),

    /// A notification from Core of pending or in-flight updates.
    UpdatesReceived(Vec<UpdateRequest>),
    /// A notification from RVI of a pending update.
    UpdateAvailable(UpdateAvailable),
    /// There are no outstanding update requests.
    NoUpdateRequests,

    /// The following packages are installed on the device.
    FoundInstalledPackages(Vec<Package>),
    /// An update on the system information was received.
    FoundSystemInfo(String),

    /// Downloading an update.
    DownloadingUpdate(Uuid),
    /// An update was downloaded.
    DownloadComplete(DownloadComplete),
    /// Downloading an update failed.
    DownloadFailed(Uuid, String),

    /// Installing an update.
    InstallingUpdate(Uuid),
    /// An update was installed.
    InstallComplete(InstallResult),
    /// The installation of an update failed.
    InstallFailed(InstallResult),
    /// An installation report was sent.
    InstallReportSent(InstallReport),

    /// An event requesting an update on all installed packages.
    InstalledPackagesNeeded,
    /// A list of installed packages was sent.
    InstalledPackagesSent,
    /// An event requesting an update on all installed software.
    InstalledSoftwareNeeded,
    /// A list of installed software was sent.
    InstalledSoftwareSent,
    /// An event requesting an update on the system information.
    SystemInfoNeeded,
    /// The system information was sent.
    SystemInfoSent,

    /// There are no new Uptane updates.
    UptaneTimestampUpdated,
    /// The updated snapshot.json metadata.
    UptaneSnapshotUpdated(HashMap<String, TufMeta>),
    /// The updated target.json metadata.
    UptaneTargetsUpdated(Verified),
    /// An update was installed to a specific ECU.
    UptaneInstallComplete(Manifests),
    /// An update was not installed to a specific ECU.
    UptaneInstallFailed(Manifests),
    /// An event requesting an external ECU to install a package.
    UptaneInstallNeeded(OstreePackage),
    /// A manifest should be sent to the Director server.
    UptaneManifestNeeded,
    /// A manifest was sent to the Director server.
    UptaneManifestSent,
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Event::UptaneTargetsUpdated(ref verified) => {
                write!(f, "UptaneTargetsUpdated(role: {}, data: {:?}, new_ver: {}, old_ver: {})",
                       verified.role, verified.data, verified.new_ver, verified.old_ver)
            }
            _ => write!(f, "{:?}", self)
        }
    }
}
