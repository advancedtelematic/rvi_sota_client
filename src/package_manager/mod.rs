pub mod deb;
pub mod ostree;
pub mod package_manager;
pub mod rpm;
pub mod test;

pub use self::package_manager::{Credentials, InstallOutcome, PackageManager, parse_package};
pub use self::test::{assert_rx, TestDir};
