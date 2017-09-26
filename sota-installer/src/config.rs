use std::str::FromStr;
use std::time::Duration;
use toml;

use installer::{Installer, InstallType};
use sota::atomic::{Secondary, TcpClient};
use sota::datatype::{Error, PrivateKey, SignatureType, SocketAddrV4, Util};


pub struct App {
    pub install_type: InstallType,
    pub oneshot: bool,
    pub config: Config,
}

impl App {
    pub fn to_secondary(&self) -> Result<Secondary, Error> {
        let primary = if let Some(ref addr) = self.config.primary {
            addr.clone()
        } else {
            "127.0.0.1:2310".parse::<SocketAddrV4>()?
        };
        let client = TcpClient::new(self.config.serial.clone(), *primary)?;

        let sig_type = if let Some(sig_type) = self.config.signature_type {
            sig_type
        } else {
            SignatureType::RsaSsaPss
        };

        let image_dir = if let Some(ref image_dir) = self.config.image_dir {
            image_dir.clone()
        } else {
            "/tmp/sota-writer-images".into()
        };

        let step = Installer {
            install_type: self.install_type.clone(),

            serial: self.config.serial.clone(),
            private_key: PrivateKey {
                keyid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
                der_key: Util::read_file(&self.config.private_key_path)?
            },
            sig_type: sig_type,
            image_dir: image_dir,
            filepath: None,
            meta: None,
        };

        let timeout = Duration::from_secs(self.config.timeout.unwrap_or(300));
        Ok(Secondary::new(client, Box::new(step), timeout, None))
    }
}


#[derive(Deserialize)]
pub struct Config {
    pub serial: String,
    pub private_key_path: String,
    pub signature_type: Option<SignatureType>,

    pub timeout: Option<u64>,
    pub primary: Option<SocketAddrV4>,
    pub image_dir: Option<String>,
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(toml::from_str(s)?)
    }
}
