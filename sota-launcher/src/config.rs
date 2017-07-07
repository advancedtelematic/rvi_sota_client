use std::collections::HashMap;
use std::str::FromStr;
use toml;
use uuid::Uuid;

use datatypes::*;


#[derive(Deserialize)]
pub struct Config {
    pub environment: Environment,
    pub play_session: PlaySession,
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}


#[derive(Deserialize)]
pub struct Targets {
    pub device: Device,
    pub targets: Vec<Target>,
}

impl FromStr for Targets {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}

impl Targets {
    pub fn as_updates(&self) -> UpdateTargets {
        let targets = self.targets
            .iter()
            .map(|target| {
                let update = Update {
                    from: None,
                    to: UpdateTarget {
                        target: target.target.clone(),
                        length: target.length,
                        checksum: Checksum { method: target.method, hash: target.hash.clone() }
                    }
                };
                (target.serial.clone(), update)
            })
            .collect::<HashMap<String, Update>>();
        UpdateTargets { targets: targets }
    }
}

#[derive(Deserialize)]
pub struct Device {
    pub device_id: Uuid,
}

impl FromStr for Device {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}

#[derive(Deserialize)]
pub struct Target {
    pub serial: String,
    pub target: String,
    pub length: u64,
    pub method: ChecksumMethod,
    pub hash: String,
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn parse_config() {
        let toml = Text::read("examples/config.toml").expect("read examples/config.toml");
        let config = toml.parse::<Config>().expect("parse config.toml");
        assert_eq!(config.environment, Environment::CI);
        assert_eq!(config.play_session.csrf_token, "1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678");
    }

    #[test]
    fn parse_targets() {
        let toml = Text::read("examples/targets.toml").expect("read examples/targets.toml");
        let targets = toml.parse::<Targets>().expect("parse targets.toml");
        assert_eq!(targets.device.device_id, "00000000-0000-0000-0000-000000000000".parse::<Uuid>().expect("uuid"));
        assert_eq!(targets.targets.len(), 2);
        assert_eq!(targets.targets[0].method, ChecksumMethod::Sha256);
        assert_eq!(&targets.targets[1].serial, "234");
    }
}
