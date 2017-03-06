use rustc_serialize::Decodable;
use std::fs::File;
use std::io::prelude::*;
use toml::{Decoder, Parser, Table};

use datatype::{Auth, ClientCredentials, Error, SocketAddr, Url};
use package_manager::PackageManager;


/// A container for all parsed configs.
#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub struct Config {
    pub auth:      Option<AuthConfig>,
    pub core:      CoreConfig,
    pub dbus:      DBusConfig,
    pub device:    DeviceConfig,
    pub gateway:   GatewayConfig,
    pub network:   NetworkConfig,
    pub provision: Option<ProvisionConfig>,
    pub rvi:       RviConfig,
    pub tls:       Option<TlsConfig>,
    pub uptane:    UptaneConfig,
}

impl Config {
    /// Read a toml config file using default values for missing sections or fields.
    pub fn load(path: &str) -> Result<Config, Error> {
        info!("Loading config file: {}", path);
        let mut file = File::open(path).map_err(Error::Io)?;
        let mut toml = String::new();
        file.read_to_string(&mut toml)?;
        Config::parse(&toml)
    }

    /// Parse a toml config using default values for missing sections or fields.
    #[allow(unused_mut)]
    pub fn parse(toml: &str) -> Result<Config, Error> {
        let table = parse_table(&toml)?;

        let mut auth:      Option<ParsedAuthConfig>      = maybe_parse_section(&table, "auth")?;
        let mut provision: Option<ParsedProvisionConfig> = maybe_parse_section(&table, "provision")?;
        let mut tls:       Option<ParsedTlsConfig>       = maybe_parse_section(&table, "tls")?;

        let mut core:    ParsedCoreConfig    = parse_section(&table, "core")?;
        let mut dbus:    ParsedDBusConfig    = parse_section(&table, "dbus")?;
        let mut device:  ParsedDeviceConfig  = parse_section(&table, "device")?;
        let mut gateway: ParsedGatewayConfig = parse_section(&table, "gateway")?;
        let mut network: ParsedNetworkConfig = parse_section(&table, "network")?;
        let mut rvi:     ParsedRviConfig     = parse_section(&table, "rvi")?;
        let mut uptane:  ParsedUptaneConfig  = parse_section(&table, "uptane")?;

        backwards_compatibility(&mut core, &mut device)?;

        Ok(Config {
            auth:      auth.map(|mut cfg| cfg.defaultify()),
            core:      core.defaultify(),
            dbus:      dbus.defaultify(),
            device:    device.defaultify(),
            gateway:   gateway.defaultify(),
            network:   network.defaultify(),
            provision: provision.map(|mut cfg| cfg.defaultify()),
            rvi:       rvi.defaultify(),
            tls:       tls.map(|mut cfg| cfg.defaultify()),
            uptane:    uptane.defaultify()
        })
    }

    /// Return the initial Auth type from the current Config.
    pub fn initial_auth(&self) -> Result<Auth, &'static str> {
        match (self.auth.as_ref(), self.tls.as_ref(), self.provision.as_ref()) {
            (Some(_), Some(_), _)       => Err("Need one of [auth] or [tls] section only."),
            (Some(_), _,       Some(_)) => Err("Need one of [auth] or [provision] section only."),
            (None,    None,    None)    => Ok(Auth::None),
            (None,    Some(_), None)    => Ok(Auth::Certificate),
            (None,    _,       Some(_)) => Ok(Auth::Provision),

            (Some(&AuthConfig { client_id: ref id, client_secret: ref secret, .. }), _, _) => {
                Ok(Auth::Credentials(ClientCredentials { client_id: id.clone(), client_secret: secret.clone() }))
            }
        }
    }
}


fn parse_table(toml: &str) -> Result<Table, Error> {
    let mut parser = Parser::new(toml);
    Ok(parser.parse().ok_or_else(move || parser.errors)?)
}

fn parse_section<T: Decodable + Default>(table: &Table, section: &str) -> Result<T, Error> {
    Ok(maybe_parse_section(table, section)?.unwrap_or(T::default()))
}

fn maybe_parse_section<T: Decodable>(table: &Table, section: &str) -> Result<Option<T>, Error> {
    table.get(section).map_or(Ok(None), |sect| {
        let mut decoder = Decoder::new(sect.clone());
        Ok(Some(T::decode(&mut decoder)?))
    })
}

fn backwards_compatibility(core:   &mut ParsedCoreConfig,
                           device: &mut ParsedDeviceConfig) -> Result<(), Error> {

    match (device.polling_interval, core.polling_sec) {
        (Some(_), Some(_)) => {
            return Err(Error::Config("core.polling_sec and device.polling_interval both set".to_string()))
        }

        (Some(interval), None) => {
            if interval > 0 {
                core.polling     = Some(true);
                core.polling_sec = Some(interval);
            } else {
                core.polling = Some(false);
            }
        }

        _ => ()
    }

    Ok(())
}


/// Trait used to overwrite any `None` fields in a config with its default value.
trait Defaultify<T: Default> {
    fn defaultify(&mut self) -> T;
}


/// The [auth] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
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

#[derive(RustcDecodable, Debug)]
struct ParsedAuthConfig {
    server:        Option<Url>,
    client_id:     Option<String>,
    client_secret: Option<String>
}

impl Default for ParsedAuthConfig {
    fn default() -> Self {
        ParsedAuthConfig {
            server:        None,
            client_id:     None,
            client_secret: None
        }
    }
}

impl Defaultify<AuthConfig> for ParsedAuthConfig {
    fn defaultify(&mut self) -> AuthConfig {
        let default = AuthConfig::default();
        AuthConfig {
            server:        self.server.take().unwrap_or(default.server),
            client_id:     self.client_id.take().unwrap_or(default.client_id),
            client_secret: self.client_secret.take().unwrap_or(default.client_secret)
        }
    }
}


/// The [core] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct CoreConfig {
    pub server:      Url,
    pub polling:     bool,
    pub polling_sec: u64
}

impl Default for CoreConfig {
    fn default() -> CoreConfig {
        CoreConfig {
            server:      "http://127.0.0.1:8080".parse().unwrap(),
            polling:     true,
            polling_sec: 10
        }
    }
}

#[derive(RustcDecodable)]
struct ParsedCoreConfig {
    server:      Option<Url>,
    polling:     Option<bool>,
    polling_sec: Option<u64>
}

impl Default for ParsedCoreConfig {
    fn default() -> Self {
        ParsedCoreConfig {
            server:      None,
            polling:     None,
            polling_sec: None
        }
    }
}

impl Defaultify<CoreConfig> for ParsedCoreConfig {
    fn defaultify(&mut self) -> CoreConfig {
        let default = CoreConfig::default();
        CoreConfig {
            server:      self.server.take().unwrap_or(default.server),
            polling:     self.polling.take().unwrap_or(default.polling),
            polling_sec: self.polling_sec.take().unwrap_or(default.polling_sec)
        }
    }
}


/// The [dbus] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
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

#[derive(RustcDecodable)]
struct ParsedDBusConfig {
    name:                  Option<String>,
    path:                  Option<String>,
    interface:             Option<String>,
    software_manager:      Option<String>,
    software_manager_path: Option<String>,
    timeout:               Option<i32>,
}

impl Default for ParsedDBusConfig {
    fn default() -> Self {
        ParsedDBusConfig {
            name:                  None,
            path:                  None,
            interface:             None,
            software_manager:      None,
            software_manager_path: None,
            timeout:               None
        }
    }
}

impl Defaultify<DBusConfig> for ParsedDBusConfig {
    fn defaultify(&mut self) -> DBusConfig {
        let default = DBusConfig::default();
        DBusConfig {
            name:                  self.name.take().unwrap_or(default.name),
            path:                  self.path.take().unwrap_or(default.path),
            interface:             self.interface.take().unwrap_or(default.interface),
            software_manager:      self.software_manager.take().unwrap_or(default.software_manager),
            software_manager_path: self.software_manager_path.take().unwrap_or(default.software_manager_path),
            timeout:               self.timeout.take().unwrap_or(default.timeout)
        }
    }
}


/// The [device] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct DeviceConfig {
    pub uuid:              String,
    pub packages_dir:      String,
    pub package_manager:   PackageManager,
    pub auto_download:     bool,
    pub certificates_path: Option<String>,
    pub system_info:       Option<String>,
}

impl Default for DeviceConfig {
    fn default() -> DeviceConfig {
        DeviceConfig {
            uuid:              "123e4567-e89b-12d3-a456-426655440000".to_string(),
            packages_dir:      "/tmp/".to_string(),
            package_manager:   PackageManager::Off,
            auto_download:     true,
            certificates_path: None,
            system_info:       None,
        }
    }
}

#[derive(RustcDecodable)]
struct ParsedDeviceConfig {
    pub uuid:              Option<String>,
    pub packages_dir:      Option<String>,
    pub package_manager:   Option<PackageManager>,
    pub auto_download:     Option<bool>,
    pub polling_interval:  Option<u64>,
    pub certificates_path: Option<String>,
    pub system_info:       Option<String>,
}

impl Default for ParsedDeviceConfig {
    fn default() -> Self {
        ParsedDeviceConfig {
            uuid:              None,
            packages_dir:      None,
            package_manager:   None,
            auto_download:     None,
            polling_interval:  None,
            certificates_path: None,
            system_info:       None,
        }
    }
}

impl Defaultify<DeviceConfig> for ParsedDeviceConfig {
    fn defaultify(&mut self) -> DeviceConfig {
        let default = DeviceConfig::default();
        DeviceConfig {
            uuid:              self.uuid.take().unwrap_or(default.uuid),
            packages_dir:      self.packages_dir.take().unwrap_or(default.packages_dir),
            package_manager:   self.package_manager.take().unwrap_or(default.package_manager),
            auto_download:     self.auto_download.take().unwrap_or(default.auto_download),
            certificates_path: self.certificates_path.take().or(default.certificates_path),
            system_info:       self.system_info.take().or(default.system_info),
        }
    }
}


/// The [gateway] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct GatewayConfig {
    pub console:   bool,
    pub dbus:      bool,
    pub http:      bool,
    pub rvi:       bool,
    pub socket:    bool,
    pub websocket: bool,
}

impl Default for GatewayConfig {
    fn default() -> GatewayConfig {
        GatewayConfig {
            console:   false,
            dbus:      false,
            http:      false,
            rvi:       false,
            socket:    false,
            websocket: false,
        }
    }
}

#[derive(RustcDecodable)]
struct ParsedGatewayConfig {
    console:   Option<bool>,
    dbus:      Option<bool>,
    http:      Option<bool>,
    rvi:       Option<bool>,
    socket:    Option<bool>,
    websocket: Option<bool>,
}

impl Default for ParsedGatewayConfig {
    fn default() -> Self {
        ParsedGatewayConfig {
            console:   None,
            dbus:      None,
            http:      None,
            rvi:       None,
            socket:    None,
            websocket: None
        }
    }
}

impl Defaultify<GatewayConfig> for ParsedGatewayConfig {
    fn defaultify(&mut self) -> GatewayConfig {
        let default = GatewayConfig::default();
        GatewayConfig {
            console:   self.console.take().unwrap_or(default.console),
            dbus:      self.dbus.take().unwrap_or(default.dbus),
            http:      self.http.take().unwrap_or(default.http),
            rvi:       self.rvi.take().unwrap_or(default.rvi),
            socket:    self.socket.take().unwrap_or(default.socket),
            websocket: self.websocket.take().unwrap_or(default.websocket)
        }
    }
}


/// The [network] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
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

#[derive(RustcDecodable)]
struct ParsedNetworkConfig {
    http_server:          Option<SocketAddr>,
    rvi_edge_server:      Option<SocketAddr>,
    socket_commands_path: Option<String>,
    socket_events_path:   Option<String>,
    websocket_server:     Option<String>
}

impl Default for ParsedNetworkConfig {
    fn default() -> Self {
        ParsedNetworkConfig {
            http_server:          None,
            rvi_edge_server:      None,
            socket_commands_path: None,
            socket_events_path:   None,
            websocket_server:     None
        }
    }
}

impl Defaultify<NetworkConfig> for ParsedNetworkConfig {
    fn defaultify(&mut self) -> NetworkConfig {
        let default = NetworkConfig::default();
        NetworkConfig {
            http_server:          self.http_server.take().unwrap_or(default.http_server),
            rvi_edge_server:      self.rvi_edge_server.take().unwrap_or(default.rvi_edge_server),
            socket_commands_path: self.socket_commands_path.take().unwrap_or(default.socket_commands_path),
            socket_events_path:   self.socket_events_path.take().unwrap_or(default.socket_events_path),
            websocket_server:     self.websocket_server.take().unwrap_or(default.websocket_server)
        }
    }
}


/// The [provision] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct ProvisionConfig {
    pub p12_path:            String,
    pub p12_password:        String,
    pub expiry_days:         u32,
    pub device_id:           Option<String>,
    pub retry_delay_seconds: u64,
}

impl Default for ProvisionConfig {
    fn default() -> Self {
        ProvisionConfig {
            p12_path:            "/usr/local/etc/sota/registration.p12".to_string(),
            p12_password:        "".to_string(),
            expiry_days:         365,
            device_id:           None,
            retry_delay_seconds: 5,
        }
    }
}

#[derive(RustcDecodable, Debug)]
struct ParsedProvisionConfig {
    p12_path:     Option<String>,
    p12_password: Option<String>,
    expiry_days:  Option<u32>,
    device_id:    Option<String>,
    retry_delay_seconds: Option<u64>,
}

impl Default for ParsedProvisionConfig {
    fn default() -> Self {
        ParsedProvisionConfig {
            p12_path:            None,
            p12_password:        None,
            expiry_days:         None,
            device_id:           None,
            retry_delay_seconds: None,
        }
    }
}

impl Defaultify<ProvisionConfig> for ParsedProvisionConfig {
    fn defaultify(&mut self) -> ProvisionConfig {
        let default = ProvisionConfig::default();
        ProvisionConfig {
            p12_path:            self.p12_path.take().unwrap_or(default.p12_path),
            p12_password:        self.p12_password.take().unwrap_or(default.p12_password),
            expiry_days:         self.expiry_days.take().unwrap_or(default.expiry_days),
            device_id:           self.device_id.take().or(default.device_id),
            retry_delay_seconds: self.retry_delay_seconds.take().unwrap_or(default.retry_delay_seconds),
        }
    }
}


/// The [rvi] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
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

#[derive(RustcDecodable)]
struct ParsedRviConfig {
    client:      Option<Url>,
    storage_dir: Option<String>,
    timeout:     Option<i64>,
}

impl Default for ParsedRviConfig {
    fn default() -> Self {
        ParsedRviConfig {
            client:      None,
            storage_dir: None,
            timeout:     None
        }
    }
}

impl Defaultify<RviConfig> for ParsedRviConfig {
    fn defaultify(&mut self) -> RviConfig {
        let default = RviConfig::default();
        RviConfig {
            client:      self.client.take().unwrap_or(default.client),
            storage_dir: self.storage_dir.take().unwrap_or(default.storage_dir),
            timeout:     self.timeout.take().or(default.timeout)
        }
    }
}


/// The [tls] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct TlsConfig {
    pub server:            Url,
    pub p12_path:          String,
    pub p12_password:      String,
    pub certificates_path: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            server:            "http://127.0.0.1:8000".parse().unwrap(),
            p12_path:          "/usr/local/etc/sota/device.p12".to_string(),
            p12_password:      "".to_string(),
            certificates_path: None,
        }
    }
}

#[derive(RustcDecodable, Debug)]
struct ParsedTlsConfig {
    server:            Option<Url>,
    p12_path:          Option<String>,
    p12_password:      Option<String>,
    certificates_path: Option<String>,
}

impl Default for ParsedTlsConfig {
    fn default() -> Self {
        ParsedTlsConfig {
            server:            None,
            p12_path:          None,
            p12_password:      None,
            certificates_path: None,
        }
    }
}

impl Defaultify<TlsConfig> for ParsedTlsConfig {
    fn defaultify(&mut self) -> TlsConfig {
        let default = TlsConfig::default();
        TlsConfig {
            server:            self.server.take().unwrap_or(default.server),
            p12_path:          self.p12_path.take().unwrap_or(default.p12_path),
            p12_password:      self.p12_password.take().unwrap_or(default.p12_password),
            certificates_path: self.certificates_path.take().or(default.certificates_path),
        }
    }
}


/// The [uptane] configuration section.
#[derive(RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct UptaneConfig {
    pub primary_ecu_serial: String,
    pub metadata_path:      String,
    pub private_key_path:   String,
    pub public_key_path:    String,
}

impl Default for UptaneConfig {
    fn default() -> UptaneConfig {
        UptaneConfig {
            primary_ecu_serial: "primary-serial".to_string(),
            metadata_path:      "/usr/local/etc/sota/metadata".to_string(),
            private_key_path:   "/usr/local/etc/sota/ecuprimary.pem".to_string(),
            public_key_path:    "/usr/local/etc/sota/ecuprimary.pub".to_string(),
        }
    }
}

#[derive(RustcDecodable)]
struct ParsedUptaneConfig {
    primary_ecu_serial: Option<String>,
    metadata_path:      Option<String>,
    private_key_path:   Option<String>,
    public_key_path:    Option<String>,
}

impl Default for ParsedUptaneConfig {
    fn default() -> ParsedUptaneConfig {
        ParsedUptaneConfig {
            primary_ecu_serial: None,
            metadata_path:      None,
            private_key_path:   None,
            public_key_path:    None,
        }
    }
}

impl Defaultify<UptaneConfig> for ParsedUptaneConfig {
    fn defaultify(&mut self) -> UptaneConfig {
        let default = UptaneConfig::default();
        UptaneConfig {
            primary_ecu_serial: self.primary_ecu_serial.take().unwrap_or(default.primary_ecu_serial),
            metadata_path:      self.metadata_path.take().unwrap_or(default.metadata_path),
            private_key_path:   self.private_key_path.take().unwrap_or(default.private_key_path),
            public_key_path:    self.public_key_path.take().unwrap_or(default.public_key_path),
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
        uuid = "123e4567-e89b-12d3-a456-426655440000"
        packages_dir = "/tmp/"
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

    const PROVISION_CONFIG: &'static str =
        r#"
        [provision]
        p12_path = "/usr/local/etc/sota/registration.p12"
        p12_password = ""
        expiry_days = 11
        retry_delay_seconds = 17
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
        server = "http://127.0.0.1:9001"
        p12_path = "/usr/local/etc/sota/device.p12"
        p12_password = ""
        "#;

    const UPTANE_CONFIG: &'static str =
        r#"
        [uptane]
        primary_ecu_serial = "primary-serial"
        metadata_path = "/usr/local/etc/sota/metadata"
        private_key_path = "/usr/local/etc/sota/ecuprimary.pem"
        public_key_path = "/usr/local/etc/sota/ecuprimary.pub"
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
            + PROVISION_CONFIG
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
