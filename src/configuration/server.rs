//! Handles the `server` section of the configuration file.

use toml;

use super::common::{get_required_key, ConfTreeParser, Result};
use http::Url;

/// Type to encode allowed keys for the `server` section of the configuration.
#[derive(Clone)]
pub struct ServerConfiguration {
    pub url: Url,
    pub polling_interval: i64,
    pub vin: String,
    pub packages_dir: String,
    pub packages_extension: String,
}

impl ConfTreeParser<ServerConfiguration> for ServerConfiguration {
    fn parse(tree: &toml::Table) -> Result<ServerConfiguration> {
        let server_tree = try!(tree.get("server")
            .ok_or("Missing required subgroup \"server\""));

        let url = try!(get_required_key(server_tree, "url", "server"));
        let polling_interval = try!(get_required_key(server_tree, "polling_interval", "server"));
        let vin = try!(get_required_key(server_tree, "vin", "server"));
        let packages_dir = try!(get_required_key(server_tree, "packages_dir", "server"));
        let packages_extension = try!(get_required_key(server_tree, "packages_extension", "server"));

        Ok(ServerConfiguration {
            url: url,
            polling_interval: polling_interval,
            vin: vin,
            packages_dir: packages_dir,
            packages_extension: packages_extension,
        })
    }
}
