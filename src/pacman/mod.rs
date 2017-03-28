pub mod deb;
pub mod ostree;
pub mod interface;
pub mod rpm;
pub mod test;

pub use self::interface::{Credentials, InstallOutcome, PackageManager, parse_package};
pub use self::test::{assert_rx, TestDir};
