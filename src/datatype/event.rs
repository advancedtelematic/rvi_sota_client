use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

use datatype::{DownloadComplete, Package, TufMeta, UpdateAvailable, UpdateReport,
               UpdateRequest, UpdateRequestId};


/// System-wide events that are broadcast to all interested parties.
#[derive(RustcEncodable, RustcDecodable, Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// General error event with a printable representation for debugging.
    Error(String),

    /// Authentication was successful.
    Authenticated,
    /// An operation failed because we are not currently authenticated.
    NotAuthenticated,
    /// Nothing was done as we are already authenticated.
    AlreadyAuthenticated,

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
    DownloadingUpdate(UpdateRequestId),
    /// An update was downloaded.
    DownloadComplete(DownloadComplete),
    /// Downloading an update failed.
    DownloadFailed(UpdateRequestId, String),

    /// Installing an update.
    InstallingUpdate(UpdateRequestId),
    /// An update was installed.
    InstallComplete(UpdateReport),
    /// The installation of an update failed.
    InstallFailed(UpdateReport),
    /// A status to signal the completion of an Ostree package installation.
    OstreeInstallComplete,

    /// An update report was sent to the Core server.
    UpdateReportSent,
    /// A list of installed packages was sent to the Core server.
    InstalledPackagesSent,
    /// A list of installed software was sent to the Core server.
    InstalledSoftwareSent,
    /// The system information was sent to the Core server.
    SystemInfoSent,

    /// A broadcast event requesting an update on externally installed software.
    InstalledSoftwareNeeded,

    /// A new Uptane client was created.
    UptaneInitialised,
    /// There are no new Uptane updates.
    UptaneTimestampUpdated,
    /// The updated snapshot.json metadata.
    UptaneSnapshotUpdated(HashMap<String, TufMeta>),
    /// The updated target.json metadata.
    UptaneTargetsUpdated(HashMap<String, TufMeta>)
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
