use rustc_serialize::Decodable;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::io::prelude::*;
use std::path::Path;
use toml;
use toml::{Decoder, Parser, Table};

use datatype::{Error, Url};
use package_manager::PackageManager;


#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub struct Config {
    pub device:  DeviceConfig,
    pub auth:    Option<AuthConfig>,
    pub gateway: GatewayConfig,
    pub ota:     OtaConfig,
}

pub fn load_config(path: &str) -> Result<Config, Error> {
    debug!("load_config: {}", path);
    match File::open(path) {
        Ok(mut file) => {
            let mut text = String::new();
            try!(file.read_to_string(&mut text));
            parse_config(&text)
        }

        Err(ref err) if err.kind() == ErrorKind::NotFound => {
            error!("config file {} not found; using default config...", path);
            Ok(Config::default())
        }

        Err(err) => Err(Error::IoError(err)),
    }
}

pub fn parse_config(toml: &str) -> Result<Config, Error> {
    let table = try!(parse_table(toml));

    let auth_cfg = if table.contains_key("auth") {
        let parsed: AuthConfig = try!(parse_section(&table, "auth"));
        Some(try!(bootstrap_credentials(parsed)))
    } else {
        None
    };

    Ok(Config {
        auth:    auth_cfg,
        device:  try!(parse_section(&table, "device")),
        ota:     try!(parse_section(&table, "ota")),
        gateway: try!(parse_section(&table, "gateway")),
    })
}

fn parse_table(toml: &str) -> Result<Table, Error> {
    let mut parser = Parser::new(&toml);
    Ok(try!(parser.parse().ok_or_else(move || parser.errors)))
}

fn parse_section<T: Decodable>(table: &Table, section: &str) -> Result<T, Error> {
    let section = try!(table.get(section).ok_or_else(|| {
        Error::ParseError(format!("parse_section, invalid section: {}", section.to_string()))
    }));
    let mut decoder = Decoder::new(section.clone());
    Ok(try!(T::decode(&mut decoder)))
}


#[derive(RustcEncodable, RustcDecodable)]
struct CredentialsFile {
    pub client_id: String,
    pub secret:    String,
}

// Read AuthConfig values from the credentials file if it exists, or write the
// current AuthConfig values to a new credentials file otherwise.
fn bootstrap_credentials(auth_cfg: AuthConfig) -> Result<AuthConfig, Error> {
    let creds = auth_cfg.credentials_file.clone();
    let path = Path::new(&creds);
    debug!("bootstrap_credentials: {:?}", path);

    let credentials = match File::open(path) {
        Ok(mut file) => {
            let mut text = String::new();
            try!(file.read_to_string(&mut text));
            let table = try!(parse_table(&text));
            try!(parse_section::<CredentialsFile>(&table, "auth"))
        }

        Err(ref err) if err.kind() == ErrorKind::NotFound => {
            let mut table   = Table::new();
            let credentials = CredentialsFile { client_id: auth_cfg.client_id, secret: auth_cfg.secret };
            table.insert("auth".to_string(), toml::encode(&credentials));

            let dir = try!(path.parent().ok_or(Error::ParseError("Invalid credentials file path".to_string())));
            try!(fs::create_dir_all(&dir));
            let mut file  = try!(File::create(path));
            let mut perms = try!(file.metadata()).permissions();
            perms.set_mode(0o600);
            try!(fs::set_permissions(path, perms));
            try!(file.write_all(&toml::encode_str(&table).into_bytes()));

            credentials
        }

        Err(err) => return Err(Error::IoError(err))
    };

    Ok(AuthConfig {
        server:           auth_cfg.server,
        client_id:        credentials.client_id,
        secret:           credentials.secret,
        credentials_file: auth_cfg.credentials_file,
    })
}


#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct AuthConfig {
    pub server:           Url,
    pub client_id:        String,
    pub secret:           String,
    pub credentials_file: String,
}

impl Default for AuthConfig {
    fn default() -> AuthConfig {
        AuthConfig {
            server:           Url::parse("http://127.0.0.1:9000").unwrap(),
            client_id:        "client-id".to_string(),
            secret:           "secret".to_string(),
            credentials_file: "/tmp/ats_credentials.toml".to_string(),
        }
    }
}


#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct DeviceConfig {
    pub uuid: String,
    pub vin:  String,
}

impl Default for DeviceConfig {
    fn default() -> DeviceConfig {
        DeviceConfig {
            uuid: "123e4567-e89b-12d3-a456-426655440000".to_string(),
            vin:  "V1234567890123456".to_string(),
        }
    }
}


#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct GatewayConfig {
    pub console:   bool,
    pub http:      bool,
    pub websocket: bool,
}

impl Default for GatewayConfig {
    fn default() -> GatewayConfig {
        GatewayConfig {
            console:   false,
            http:      false,
            websocket: true,
        }
    }
}


#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct OtaConfig {
    pub server:           Url,
    pub polling_interval: u64,
    pub packages_dir:     String,
    pub package_manager:  PackageManager,
}

impl Default for OtaConfig {
    fn default() -> OtaConfig {
        OtaConfig {
            server:           Url::parse("http://127.0.0.1:8080").unwrap(),
            polling_interval: 10,
            packages_dir:     "/tmp/".to_string(),
            package_manager:  PackageManager::Dpkg,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    const AUTH_CONFIG: &'static str =
        r#"
        [auth]
        server = "http://127.0.0.1:9000"
        client_id = "client-id"
        secret = "secret"
        credentials_file = "/tmp/ats_credentials.toml"
        "#;

    const DEVICE_CONFIG: &'static str =
        r#"
        [device]
        uuid = "123e4567-e89b-12d3-a456-426655440000"
        vin = "V1234567890123456"
        "#;

    const GATEWAY_CONFIG: &'static str =
        r#"
        [gateway]
        console = false
        http = false
        websocket = true
        "#;

    const OTA_CONFIG: &'static str =
        r#"
        [ota]
        server = "http://127.0.0.1:8080"
        polling_interval = 10
        packages_dir = "/tmp/"
        package_manager = "dpkg"
        "#;

    #[test]
    fn parse_default_config() {
        let config = String::new() + DEVICE_CONFIG + GATEWAY_CONFIG + OTA_CONFIG;
        assert_eq!(parse_config(&config).unwrap(), Config::default());
    }

    #[test]
    fn parse_example_config() {
        let config = String::new() + AUTH_CONFIG + DEVICE_CONFIG + GATEWAY_CONFIG + OTA_CONFIG;
        assert_eq!(load_config("sota.toml").unwrap(), parse_config(&config).unwrap());
    }

    #[test]
    fn bad_path_yields_default_config() {
        assert_eq!(load_config("").unwrap(), Config::default())
    }
}
