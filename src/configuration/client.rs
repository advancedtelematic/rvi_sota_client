//! Handles the `client` section of the configuration file.

use toml;

use super::common::{get_required_key, get_optional_key, ConfTreeParser, Result};

/// Type to encode allowed keys for the `client` section of the configuration.
#[derive(Clone)]
pub struct ClientConfiguration {
    /// Directory where chunks and packages will be stored.
    pub storage_dir: String,
    /// The full URL where RVI can be reached.
    pub rvi_url: Option<String>,
    /// The `host:port` combination where the client should bind and listen for incoming RVI calls.
    pub edge_url: Option<String>,
    /// How long to wait for further server messages before the `Transfer` will be dropped.
    pub timeout: Option<i64>,
    /// Index of the RVI service URL, that holds the VIN for this device.
    pub vin_match: i32,
    /// Whether to use the HTTP interface to the Sota server instead of RVI
    pub http: bool,
}

impl ConfTreeParser<ClientConfiguration> for ClientConfiguration {
    fn parse(tree: &toml::Table) -> Result<ClientConfiguration> {
        let client_tree = try!(tree.get("client")
            .ok_or("Missing required subgroup \"client\""));

        let storage_dir = try!(get_required_key(client_tree, "storage_dir", "client"));
        let rvi_url = try!(get_optional_key(client_tree, "rvi_url", "client"));
        let edge_url = try!(get_optional_key(client_tree, "edge_url", "client"));
        let timeout = try!(get_optional_key(client_tree, "timeout", "client"));
        let vin_match = try!(get_optional_key(client_tree, "vin_match", "client"));
        let http = try!(get_optional_key(client_tree, "http", "client"));

        Ok(ClientConfiguration {
            storage_dir: storage_dir,
            rvi_url: rvi_url,
            edge_url: edge_url,
            timeout: timeout,
            vin_match: vin_match.unwrap_or(2),
            http: http.unwrap_or(false)
        })
    }
}

#[cfg(test)] static STORAGE: &'static str = "/var/sota";
#[cfg(test)] static RVI: &'static str = "/http://localhost:8901";
#[cfg(test)] static EDGE: &'static str = "localhost:9080";
#[cfg(test)] static TIMEOUT: i64 = 10;
#[cfg(test)] static VIN: i32 = 3;
#[cfg(test)] static HTTP: bool = false;

#[cfg(test)]
pub fn gen_valid_conf() -> String {
    format!(r#"
    [client]
    storage_dir = "{}"
    rvi_url = "{}"
    edge_url = "{}"
    timeout = {}
    vin_match = {}
    http = {}
    "#, STORAGE, RVI, EDGE, TIMEOUT, VIN, HTTP)
}

#[cfg(test)]
pub fn assert_conf(configuration: &ClientConfiguration) -> bool {
    assert_eq!(&configuration.storage_dir, STORAGE);
    assert_eq!(&configuration.rvi_url.clone().unwrap(), RVI);
    assert_eq!(&configuration.edge_url.clone().unwrap(), EDGE);
    assert_eq!(configuration.timeout.unwrap(), TIMEOUT);
    assert_eq!(configuration.vin_match, VIN);
    true
}

#[cfg(test)]
pub mod test {
    use super::*;
    use super::{STORAGE, RVI, EDGE, TIMEOUT, VIN};
    use configuration::common::{ConfTreeParser, read_tree};

    #[test]
    fn it_requires_the_storage_dir_key() {
        test_init!();
        let data = format!(r#"
        [client]
        rvi_url = "{}"
        edge_url = "{}"
        timeout = {}
        vin_match = {}
        "#, RVI, EDGE, TIMEOUT, VIN);

        let tree = read_tree(&data).unwrap();
        match ClientConfiguration::parse(&tree) {
            Ok(..) => panic!("Accepted invalid configuration!"),
            Err(e) => {
                assert_eq!(e,
                           "Missing required key \"storage_dir\" in \"client\""
                           .to_string());
            }
        };
    }

    #[test]
    fn it_doesnt_require_the_rvi_url_key() {
        test_init!();
        let data = format!(r#"
        [client]
        storage_dir = "{}"
        edge_url = "{}"
        timeout = {}
        vin_match = {}
        "#, STORAGE, EDGE, TIMEOUT, VIN);

        let tree = read_tree(&data).unwrap();
        let configuration = ClientConfiguration::parse(&tree).unwrap();
        assert_eq!(&configuration.storage_dir, STORAGE);
        assert_eq!(configuration.rvi_url, None);
        assert_eq!(&configuration.edge_url.unwrap(), EDGE);
        assert_eq!(configuration.timeout.unwrap(), TIMEOUT);
        assert_eq!(configuration.vin_match, VIN);
    }

    #[test]
    fn it_doesnt_require_the_edge_url_key() {
        test_init!();
        let data = format!(r#"
        [client]
        storage_dir = "{}"
        rvi_url = "{}"
        timeout = {}
        vin_match = {}
        "#, STORAGE, RVI, TIMEOUT, VIN);

        let tree = read_tree(&data).unwrap();
        let configuration = ClientConfiguration::parse(&tree).unwrap();
        assert_eq!(&configuration.storage_dir, STORAGE);
        assert_eq!(&configuration.rvi_url.unwrap(), RVI);
        assert_eq!(configuration.edge_url, None);
        assert_eq!(configuration.vin_match, VIN);
    }

    #[test]
    fn it_doesnt_require_the_timeout_key() {
        test_init!();
        let data = format!(r#"
        [client]
        storage_dir = "{}"
        rvi_url = "{}"
        edge_url = "{}"
        vin_match = {}
        "#, STORAGE, RVI, EDGE, VIN);

        let tree = read_tree(&data).unwrap();
        let configuration = ClientConfiguration::parse(&tree).unwrap();
        assert_eq!(&configuration.storage_dir, STORAGE);
        assert_eq!(&configuration.rvi_url.unwrap(), RVI);
        assert_eq!(&configuration.edge_url.unwrap(), EDGE);
        assert_eq!(configuration.timeout, None);
        assert_eq!(configuration.vin_match, VIN);
    }

    #[test]
    fn it_doesnt_require_the_vin_match_key_and_uses_a_default() {
        test_init!();
        let data = format!(r#"
        [client]
        storage_dir = "{}"
        rvi_url = "{}"
        edge_url = "{}"
        timeout = {}
        "#, STORAGE, RVI, EDGE, TIMEOUT);

        let tree = read_tree(&data).unwrap();
        let configuration = ClientConfiguration::parse(&tree).unwrap();
        assert_eq!(&configuration.storage_dir, STORAGE);
        assert_eq!(&configuration.rvi_url.unwrap(), RVI);
        assert_eq!(&configuration.edge_url.unwrap(), EDGE);
        assert_eq!(configuration.timeout.unwrap(), TIMEOUT);
        assert_eq!(configuration.vin_match, 2);
    }
}
