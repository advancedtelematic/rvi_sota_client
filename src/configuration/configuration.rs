//! Main logic for parsing the configuration file

use toml;
use std::io::prelude::*;
use std::path::PathBuf;
use std::fs::OpenOptions;
use std::env;

use super::common::{ConfTreeParser, format_parser_error, stringify, Result};
use super::client::ClientConfiguration;
use super::server::ServerConfiguration;
use super::dbus::DBusConfiguration;

/// Type to encode the full configuration.
#[derive(Clone)]
pub struct Configuration {
    /// The `client` section of the configuration
    pub client: ClientConfiguration,
    /// The `server` section of the configuration
    pub server: ServerConfiguration,
    /// The `dbus` section of the configuration
    pub dbus: DBusConfiguration
}

impl Configuration {
    /// Try to read the configuration from the provided path and parse it into a `Configuration`
    /// object. Returns the parsed `Configuration` on success or the first error message
    /// encountered while reading or parsing the configuration file.
    ///
    /// # Arguments
    /// * `path`: Path to the location of the configuration file.
    pub fn read(path: &str) -> Result<Configuration> {
        let path = PathBuf::from(path);
        let mut f = try!(OpenOptions::new().open(path).map_err(stringify));
        let mut buf = Vec::new();
        try!(f.read_to_end(&mut buf).map_err(stringify));
        let data = try!(String::from_utf8(buf).map_err(stringify));
        Configuration::parse(&data)
    }

    /// Try to parse the given string to a `Configuration`.
    ///
    /// # Arguments
    /// * `conf`: The configuration to parse.
    pub fn parse(conf: &str) -> Result<Configuration> {
        let mut parser = toml::Parser::new(conf);
        let tree = try!(parser.parse().ok_or(format_parser_error(&parser)));

        let client = try!(ClientConfiguration::parse(&tree));
        let server = try!(ServerConfiguration::parse(&tree));
        let dbus   = try!(DBusConfiguration::parse(&tree));

        Ok(Configuration {
            client: client,
            server: server,
            dbus: dbus
        })
    }

    /// Try to find the configuration file in different paths. First
    /// `$XDG_CONFIG_HOME/sota/client.toml` is tried, then `$HOME/.sota/client.toml` returns
    /// `$PWD/.sota/client.toml` if none of the above can be found. The case where this file also
    /// doesn't exist should be handled by [`read`](#method.read).
    pub fn default_path() -> String {
        match env::var_os("XDG_CONFIG_HOME")
            .and_then(|s| s.into_string().ok()) {
            Some(val) => { return val + "/sota/client.toml"; },
            None => { error!("$XDG_CONFIG_HOME is not set"); }
        }

        match env::var_os("HOME").and_then(|s| s.into_string().ok()) {
            Some(val) => {
                warn!("Falling back to $HOME/.config");
                return val + "/.sota/client.toml";
            },
            None => { error!("$HOME is not set"); }
        }

        warn!("Falling back to $PWD");
        ".sota/client.toml".to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use configuration::client;
    use configuration::dbus;

    #[test]
    fn it_uses_fallbacks_for_its_configuration() {
        test_init!();
        env::remove_var("XDG_CONFIG_HOME");
        env::set_var("XDG_CONFIG_HOME", "/some/thing");
        assert_eq!(Configuration::default_path(),
                   "/some/thing/sota/client.toml".to_string());
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("HOME");
        env::set_var("HOME", "/some/thing");
        assert_eq!(Configuration::default_path(),
                   "/some/thing/.sota/client.toml".to_string());
        env::remove_var("XDG_CONFIG_HOME");
        env::remove_var("HOME");
        assert_eq!(Configuration::default_path(),
                   ".sota/client.toml".to_string());
    }

    #[test]
    fn it_correctly_parses_a_valid_configuration() {
        test_init!();
        let data = format!("{}\n{}",
        client::gen_valid_conf(),
        dbus::gen_valid_conf());

        let configuration = Configuration::parse(&data).unwrap();
        assert!(client::assert_conf(&configuration.client));
        assert!(dbus::assert_conf(&configuration.dbus));
    }

    #[test]
    fn it_ignores_extra_keys() {
        test_init!();
        let data = format!(r#"
        {}
        test_key = "hello world"

        {}
        test_key = "see ya world"
        "#, client::gen_valid_conf(),
        dbus::gen_valid_conf());

        let configuration = Configuration::parse(&data).unwrap();
        assert!(client::assert_conf(&configuration.client));
        assert!(dbus::assert_conf(&configuration.dbus));
    }

    #[test]
    fn it_ignores_extra_groups() {
        test_init!();
        let data = format!(r#"
        {}

        {}

        [test]
        test_key = "hello world"
        "#, client::gen_valid_conf(),
        dbus::gen_valid_conf());

        let configuration = Configuration::parse(&data).unwrap();
        assert!(client::assert_conf(&configuration.client));
        assert!(dbus::assert_conf(&configuration.dbus));
    }

    #[test]
    fn it_requires_the_client_group() {
        test_init!();
        let data = format!("{}", dbus::gen_valid_conf());
        match Configuration::parse(&data) {
            Ok(..) => panic!("Accepted invalid configuration!"),
            Err(e) => {
                assert_eq!(e, "Missing required subgroup \"client\""
                              .to_string());
            }
        };
    }

    #[test]
    fn it_requires_the_dbus_group() {
        test_init!();
        let data = format!("{}", client::gen_valid_conf());
        match Configuration::parse(&data) {
            Ok(..) => panic!("Accepted invalid configuration!"),
            Err(e) => {
                assert_eq!(e, "Missing required subgroup \"dbus\""
                              .to_string());
            }
        };
    }
}
