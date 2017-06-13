use std::fs::File;
use std::io::prelude::*;
use std::ops::Deref;
use std::net::Ipv4Addr;
use toml;
use uuid::Uuid;

use datatype::{Auth, ClientCredentials, Error, SocketAddr, Url};
use http::TlsData;
use pacman::PacMan;


/// A container for all parsed configs.
#[derive(Deserialize, Default, PartialEq, Eq, Debug, Clone)]
pub struct Config {
    pub auth:    Option<AuthConfig>,
    pub core:    CoreConfig,
    pub dbus:    DBusConfig,
    pub device:  DeviceConfig,
    pub gateway: GatewayConfig,
    pub network: NetworkConfig,
    pub rvi:     RviConfig,
    pub tls:     Option<TlsConfig>,
    pub uptane:  UptaneConfig,
}

impl Config {
    /// Read a toml config file using default values for missing sections or fields.
    pub fn load(path: &str) -> Result<Config, Error> {
        info!("Loading config file: {}", path);
        let mut file = File::open(path).map_err(|err| Error::Config(format!("couldn't open config: {}", err)))?;
        let mut toml = String::new();
        file.read_to_string(&mut toml).map_err(|err| Error::Config(format!("couldn't read config: {}", err)))?;
        Config::parse(&toml)
    }

    /// Parse a toml config using default values for missing sections or fields.
    pub fn parse(toml: &str) -> Result<Config, Error> {
        let mut partial: PartialConfig = toml::from_str(toml)?;
        partial.backwards_compatibility()?;
        Ok(partial.into_config())
    }

    /// Return the initial Auth type from the current Config.
    pub fn initial_auth(&self) -> Result<Auth, &'static str> {
        match (self.auth.as_ref(), self.tls.as_ref()) {
            (None,    None)    => Ok(Auth::None),
            (None,    Some(_)) => Ok(Auth::Certificate),
            (Some(_), Some(_)) => Err("Need one of [auth] or [tls] section only."),
            (Some(&AuthConfig { client_id: ref id, client_secret: ref secret, .. }), None) => {
                Ok(Auth::Credentials(ClientCredentials { client_id: id.clone(), client_secret: secret.clone() }))
            }
        }
    }

    /// Return the certificates used for TLS connections from the current Config.
    pub fn tls_data(&self) -> TlsData {
        if let Some(ref tls) = self.tls {
            TlsData {
                ca_file:   Some(&tls.ca_file),
                cert_file: Some(&tls.cert_file),
                pkey_file: Some(&tls.pkey_file),
            }
        } else {
            TlsData {
                ca_file:   self.core.ca_file.as_ref().map(Deref::deref),
                cert_file: None,
                pkey_file: None,
            }
        }
    }
}


#[derive(Deserialize)]
struct PartialConfig {
    pub auth:    Option<ParsedAuthConfig>,
    pub core:    Option<ParsedCoreConfig>,
    pub dbus:    Option<ParsedDBusConfig>,
    pub device:  Option<ParsedDeviceConfig>,
    pub gateway: Option<ParsedGatewayConfig>,
    pub network: Option<ParsedNetworkConfig>,
    pub rvi:     Option<ParsedRviConfig>,
    pub tls:     Option<ParsedTlsConfig>,
    pub uptane:  Option<ParsedUptaneConfig>,
}

impl PartialConfig {
    fn into_config(self) -> Config {
        Config {
            auth:    self.auth.map(|cfg| cfg.defaultify()),
            core:    self.core.map(|cfg| cfg.defaultify()).unwrap_or_default(),
            dbus:    self.dbus.map(|cfg| cfg.defaultify()).unwrap_or_default(),
            device:  self.device.map(|cfg| cfg.defaultify()).unwrap_or_default(),
            gateway: self.gateway.map(|cfg| cfg.defaultify()).unwrap_or_default(),
            network: self.network.map(|cfg| cfg.defaultify()).unwrap_or_default(),
            rvi:     self.rvi.map(|cfg| cfg.defaultify()).unwrap_or_default(),
            tls:     self.tls.map(|cfg| cfg.defaultify()),
            uptane:  self.uptane.map(|cfg| cfg.defaultify()).unwrap_or_default(),
        }
    }

    fn backwards_compatibility(&mut self) -> Result<(), Error> {
        if let (Some(ref mut core), Some(ref mut device)) = (self.core.as_mut(), self.device.as_mut()) {
            // device.polling_interval -> core.polling_sec
            match (device.polling_interval, core.polling_sec) {
                (Some(time), None) => if time > 0 {
                    core.polling     = Some(true);
                    core.polling_sec = Some(time);
                } else {
                    core.polling = Some(false);
                },
                (Some(_), Some(_)) => Err(Error::Config("core.polling_sec and device.polling_interval both set".to_string()))?,
                _ => ()
            }

            // device.certificates_path -> core.ca_file
            match (device.certificates_path.as_mut(), core.ca_file.as_mut()) {
                (Some(path), None) => { core.ca_file = Some(path.clone()) }
                (Some(_), Some(_)) => Err(Error::Config("core.ca_file and device.certificates_path both set".to_string()))?,
                _ => ()
            }
        }

        Ok(())
    }
}


/// Trait used to overwrite any `None` fields in a config with its default value.
trait Defaultify<T: Default> {
    fn defaultify(self) -> T;
}


/// The [auth] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct AuthConfig {
    pub server:        Url,
    pub client_id:     String,
    pub client_secret: String
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            server:        "http://127.0.0.1:9001".parse().unwrap(),
            client_id:     "client-id".to_string(),
            client_secret: "client-secret".to_string()
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedAuthConfig {
    server:        Option<Url>,
    client_id:     Option<String>,
    client_secret: Option<String>
}

impl Defaultify<AuthConfig> for ParsedAuthConfig {
    fn defaultify(self) -> AuthConfig {
        let default = AuthConfig::default();
        AuthConfig {
            server:        self.server.unwrap_or(default.server),
            client_id:     self.client_id.unwrap_or(default.client_id),
            client_secret: self.client_secret.unwrap_or(default.client_secret)
        }
    }
}


/// The [core] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct CoreConfig {
    pub server:      Url,
    pub polling:     bool,
    pub polling_sec: u64,
    pub ca_file:     Option<String>,
}

impl Default for CoreConfig {
    fn default() -> CoreConfig {
        CoreConfig {
            server:      "http://127.0.0.1:8080".parse().unwrap(),
            polling:     true,
            polling_sec: 10,
            ca_file:     None,
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedCoreConfig {
    server:      Option<Url>,
    polling:     Option<bool>,
    polling_sec: Option<u64>,
    ca_file:     Option<String>,
}

impl Defaultify<CoreConfig> for ParsedCoreConfig {
    fn defaultify(self) -> CoreConfig {
        let default = CoreConfig::default();
        CoreConfig {
            server:      self.server.unwrap_or(default.server),
            polling:     self.polling.unwrap_or(default.polling),
            polling_sec: self.polling_sec.unwrap_or(default.polling_sec),
            ca_file:     self.ca_file.or(default.ca_file),
        }
    }
}


/// The [dbus] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct DBusConfig {
    pub name:                  String,
    pub path:                  String,
    pub interface:             String,
    pub software_manager:      String,
    pub software_manager_path: String,
    pub timeout:               i32,
}

impl Default for DBusConfig {
    fn default() -> DBusConfig {
        DBusConfig {
            name:                  "org.genivi.SotaClient".to_string(),
            path:                  "/org/genivi/SotaClient".to_string(),
            interface:             "org.genivi.SotaClient".to_string(),
            software_manager:      "org.genivi.SoftwareLoadingManager".to_string(),
            software_manager_path: "/org/genivi/SoftwareLoadingManager".to_string(),
            timeout:               60
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedDBusConfig {
    name:                  Option<String>,
    path:                  Option<String>,
    interface:             Option<String>,
    software_manager:      Option<String>,
    software_manager_path: Option<String>,
    timeout:               Option<i32>,
}

impl Defaultify<DBusConfig> for ParsedDBusConfig {
    fn defaultify(self) -> DBusConfig {
        let default = DBusConfig::default();
        DBusConfig {
            name:                  self.name.unwrap_or(default.name),
            path:                  self.path.unwrap_or(default.path),
            interface:             self.interface.unwrap_or(default.interface),
            software_manager:      self.software_manager.unwrap_or(default.software_manager),
            software_manager_path: self.software_manager_path.unwrap_or(default.software_manager_path),
            timeout:               self.timeout.unwrap_or(default.timeout)
        }
    }
}


/// The [device] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct DeviceConfig {
    pub uuid:            Uuid,
    pub packages_dir:    String,
    pub package_manager: PacMan,
    pub auto_download:   bool,
    pub system_info:     Option<String>,
}

impl Default for DeviceConfig {
    fn default() -> DeviceConfig {
        DeviceConfig {
            uuid:            Uuid::default(),
            packages_dir:    "/tmp".into(),
            package_manager: PacMan::Off,
            auto_download:   true,
            system_info:     None,
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedDeviceConfig {
    pub uuid:              Option<Uuid>,
    pub packages_dir:      Option<String>,
    pub package_manager:   Option<PacMan>,
    pub auto_download:     Option<bool>,
    pub system_info:       Option<String>,
    pub polling_interval:  Option<u64>,
    pub certificates_path: Option<String>,
}

impl Defaultify<DeviceConfig> for ParsedDeviceConfig {
    fn defaultify(self) -> DeviceConfig {
        let default = DeviceConfig::default();
        DeviceConfig {
            uuid:            self.uuid.unwrap_or(default.uuid),
            packages_dir:    self.packages_dir.unwrap_or(default.packages_dir),
            package_manager: self.package_manager.unwrap_or(default.package_manager),
            auto_download:   self.auto_download.unwrap_or(default.auto_download),
            system_info:     self.system_info.or(default.system_info),
        }
    }
}


/// The [gateway] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct GatewayConfig {
    pub console:   bool,
    pub dbus:      bool,
    pub http:      bool,
    pub rvi:       bool,
    pub socket:    bool,
    pub websocket: bool,
}

#[derive(Deserialize, Default)]
struct ParsedGatewayConfig {
    console:   Option<bool>,
    dbus:      Option<bool>,
    http:      Option<bool>,
    rvi:       Option<bool>,
    socket:    Option<bool>,
    websocket: Option<bool>,
}

impl Defaultify<GatewayConfig> for ParsedGatewayConfig {
    fn defaultify(self) -> GatewayConfig {
        let default = GatewayConfig::default();
        GatewayConfig {
            console:   self.console.unwrap_or(default.console),
            dbus:      self.dbus.unwrap_or(default.dbus),
            http:      self.http.unwrap_or(default.http),
            rvi:       self.rvi.unwrap_or(default.rvi),
            socket:    self.socket.unwrap_or(default.socket),
            websocket: self.websocket.unwrap_or(default.websocket)
        }
    }
}


/// The [network] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct NetworkConfig {
    pub http_server:          SocketAddr,
    pub rvi_edge_server:      SocketAddr,
    pub socket_commands_path: String,
    pub socket_events_path:   String,
    pub websocket_server:     String
}

impl Default for NetworkConfig {
    fn default() -> NetworkConfig {
        NetworkConfig {
            http_server:          "127.0.0.1:8888".parse().unwrap(),
            rvi_edge_server:      "127.0.0.1:9999".parse().unwrap(),
            socket_commands_path: "/tmp/sota-commands.socket".to_string(),
            socket_events_path:   "/tmp/sota-events.socket".to_string(),
            websocket_server:     "127.0.0.1:3012".to_string()
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedNetworkConfig {
    http_server:          Option<SocketAddr>,
    rvi_edge_server:      Option<SocketAddr>,
    socket_commands_path: Option<String>,
    socket_events_path:   Option<String>,
    websocket_server:     Option<String>
}

impl Defaultify<NetworkConfig> for ParsedNetworkConfig {
    fn defaultify(self) -> NetworkConfig {
        let default = NetworkConfig::default();
        NetworkConfig {
            http_server:          self.http_server.unwrap_or(default.http_server),
            rvi_edge_server:      self.rvi_edge_server.unwrap_or(default.rvi_edge_server),
            socket_commands_path: self.socket_commands_path.unwrap_or(default.socket_commands_path),
            socket_events_path:   self.socket_events_path.unwrap_or(default.socket_events_path),
            websocket_server:     self.websocket_server.unwrap_or(default.websocket_server)
        }
    }
}


/// The [rvi] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct RviConfig {
    pub client:      Url,
    pub storage_dir: String,
    pub timeout:     Option<i64>,
}

impl Default for RviConfig {
    fn default() -> RviConfig {
        RviConfig {
            client:      "http://127.0.0.1:8901".parse().unwrap(),
            storage_dir: "/usr/local/etc/sota/rvi".to_string(),
            timeout:     None,
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedRviConfig {
    client:      Option<Url>,
    storage_dir: Option<String>,
    timeout:     Option<i64>,
}

impl Defaultify<RviConfig> for ParsedRviConfig {
    fn defaultify(self) -> RviConfig {
        let default = RviConfig::default();
        RviConfig {
            client:      self.client.unwrap_or(default.client),
            storage_dir: self.storage_dir.unwrap_or(default.storage_dir),
            timeout:     self.timeout.or(default.timeout)
        }
    }
}


/// The [tls] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct TlsConfig {
    pub server:    Url,
    pub ca_file:   String,
    pub cert_file: String,
    pub pkey_file: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            server:    "http://localhost:8000".parse().unwrap(),
            ca_file:   "/usr/local/etc/sota/ca.crt".to_string(),
            cert_file: "/usr/local/etc/sota/device.crt".to_string(),
            pkey_file: "/usr/local/etc/sota/device.pem".to_string(),
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedTlsConfig {
    server:    Option<Url>,
    ca_file:   Option<String>,
    cert_file: Option<String>,
    pkey_file: Option<String>,
}

impl Defaultify<TlsConfig> for ParsedTlsConfig {
    fn defaultify(self) -> TlsConfig {
        let default = TlsConfig::default();
        TlsConfig {
            server:    self.server.unwrap_or(default.server),
            ca_file:   self.ca_file.unwrap_or(default.ca_file),
            cert_file: self.cert_file.unwrap_or(default.cert_file),
            pkey_file: self.pkey_file.unwrap_or(default.pkey_file),
        }
    }
}


/// The [uptane] configuration section.
#[derive(Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct UptaneConfig {
    pub director_server:    Url,
    pub repo_server:        Url,
    pub primary_ecu_serial: String,
    pub metadata_path:      String,
    pub private_key_path:   String,
    pub public_key_path:    String,
    pub multicast_address:  Ipv4Addr,
    pub multicast_port:     u16,
    pub atomic_timeout_sec: u64,
}

impl Default for UptaneConfig {
    fn default() -> UptaneConfig {
        UptaneConfig {
            director_server:    "http://localhost:8001/director".parse().unwrap(),
            repo_server:        "http://localhost:8002/repo".parse().unwrap(),
            primary_ecu_serial: "primary-serial".to_string(),
            metadata_path:      "/usr/local/etc/sota/metadata".to_string(),
            private_key_path:   "/usr/local/etc/sota/ecuprimary.pem".to_string(),
            public_key_path:    "/usr/local/etc/sota/ecuprimary.pub".to_string(),
            multicast_address:  "224.0.0.101".parse().unwrap(),
            multicast_port:     9999,
            atomic_timeout_sec: 60,
        }
    }
}

#[derive(Deserialize, Default)]
struct ParsedUptaneConfig {
    director_server:    Option<Url>,
    repo_server:        Option<Url>,
    primary_ecu_serial: Option<String>,
    metadata_path:      Option<String>,
    private_key_path:   Option<String>,
    public_key_path:    Option<String>,
    multicast_address:  Option<Ipv4Addr>,
    multicast_port:     Option<u16>,
    atomic_timeout_sec: Option<u64>,
}

impl Defaultify<UptaneConfig> for ParsedUptaneConfig {
    fn defaultify(self) -> UptaneConfig {
        let default = UptaneConfig::default();
        UptaneConfig {
            director_server:    self.director_server.unwrap_or(default.director_server),
            repo_server:        self.repo_server.unwrap_or(default.repo_server),
            primary_ecu_serial: self.primary_ecu_serial.unwrap_or(default.primary_ecu_serial),
            metadata_path:      self.metadata_path.unwrap_or(default.metadata_path),
            private_key_path:   self.private_key_path.unwrap_or(default.private_key_path),
            public_key_path:    self.public_key_path.unwrap_or(default.public_key_path),
            multicast_address:  self.multicast_address.unwrap_or(default.multicast_address),
            multicast_port:     self.multicast_port.unwrap_or(default.multicast_port),
            atomic_timeout_sec: self.atomic_timeout_sec.unwrap_or(default.atomic_timeout_sec),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    const AUTH_CONFIG: &'static str =
        r#"
        [auth]
        server = "http://127.0.0.1:9001"
        client_id = "client-id"
        client_secret = "client-secret"
        "#;

    const CORE_CONFIG: &'static str =
        r#"
        [core]
        server = "http://127.0.0.1:8080"
        polling = true
        polling_sec = 10
        "#;

    const DBUS_CONFIG: &'static str =
        r#"
        [dbus]
        name = "org.genivi.SotaClient"
        path = "/org/genivi/SotaClient"
        interface = "org.genivi.SotaClient"
        software_manager = "org.genivi.SoftwareLoadingManager"
        software_manager_path = "/org/genivi/SoftwareLoadingManager"
        timeout = 60
        "#;

    const DEVICE_CONFIG: &'static str =
        r#"
        [device]
        uuid = "00000000-0000-0000-0000-000000000000"
        packages_dir = "/tmp"
        package_manager = "off"
        "#;

    const GATEWAY_CONFIG: &'static str =
        r#"
        [gateway]
        console = false
        dbus = false
        http = false
        rvi = false
        socket = false
        websocket = false
        "#;

    const NETWORK_CONFIG: &'static str =
        r#"
        [network]
        http_server = "127.0.0.1:8888"
        rvi_edge_server = "127.0.0.1:9999"
        socket_commands_path = "/tmp/sota-commands.socket"
        socket_events_path = "/tmp/sota-events.socket"
        websocket_server = "127.0.0.1:3012"
        "#;

    const RVI_CONFIG: &'static str =
        r#"
        [rvi]
        client = "http://127.0.0.1:8901"
        storage_dir = "/usr/local/etc/sota/rvi"
        "#;

    const TLS_CONFIG: &'static str =
        r#"
        [tls]
        server = "http://localhost:8000"
        ca_file = "/usr/local/etc/sota/ca.crt"
        cert_file = "/usr/local/etc/sota/device.crt"
        pkey_file = "/usr/local/etc/sota/device.pem"
        "#;

    const UPTANE_CONFIG: &'static str =
        r#"
        [uptane]
        director_server = "http://localhost:8001/director"
        repo_server = "http://localhost:8002/repo"
        primary_ecu_serial = "primary-serial"
        metadata_path = "/usr/local/etc/sota/metadata"
        private_key_path = "/usr/local/etc/sota/ecuprimary.pem"
        public_key_path = "/usr/local/etc/sota/ecuprimary.pub"
        multicast_address = "224.0.0.101"
        multicast_port = 9999
        atomic_timeout_sec = 60
        "#;


    #[test]
    fn empty_config() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn default_config() {
        assert_eq!(Config::load("tests/config/default.toml").unwrap(), Config::default());
    }

    #[test]
    fn default_configs() {
        let configs = String::new()
            + CORE_CONFIG
            + DBUS_CONFIG
            + DEVICE_CONFIG
            + GATEWAY_CONFIG
            + NETWORK_CONFIG
            + RVI_CONFIG
            + UPTANE_CONFIG;
        assert_eq!(Config::parse(&configs).unwrap(), Config::default());
    }

    #[test]
    fn auth_configs() {
        let configs = String::new()
            + AUTH_CONFIG
            + TLS_CONFIG;
        assert_eq!(Config::load("tests/config/auth.toml").unwrap(), Config::parse(&configs).unwrap());
    }

    #[test]
    fn backwards_compatible_config() {
        let config = Config::load("tests/config/old.toml").unwrap();
        assert_eq!(config.core.polling, true);
        assert_eq!(config.core.polling_sec, 10);
    }
}
