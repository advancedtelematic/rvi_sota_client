use json;
use serde::{self, Deserialize, Deserializer};
use std::fs;
use std::str::FromStr;

use sota::atomic::{Payload, State, Step, StepData};
use sota::images::{ImageMeta, ImageWriter};
use sota::datatype::{EcuCustom, EcuVersion, Error, InstallOutcome, PrivateKey,
                     SignatureType, TufImage, TufMeta};


const IMAGE_DIR: &'static str = "/tmp/sota-writer-images";


#[derive(PartialEq, Clone, Copy, Debug)]
pub enum InstallType {
    FetchImage,
}

impl FromStr for InstallType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_ref() {
            "fetchimage" => Ok(InstallType::FetchImage),
            _ => Err(Error::Parse(format!("unknown installer type: {}", s)))
        }
    }
}

impl<'de> Deserialize<'de> for InstallType {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(de)?;
        s.parse().map_err(|err| serde::de::Error::custom(format!("{}", err)))
    }
}


/// An `Installer` will delegate at each `State` transition to a function that
/// will take the appropriate action based on the `InstallType`.
pub struct Installer {
    pub serial: String,
    pub install_type: InstallType,
    pub private_key: PrivateKey,
    pub sig_type: SignatureType,
}

impl Step for Installer {
    fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
        info!("Serial {} Moving to state {:?}", self.serial, state);
        match self.install_type {
            InstallType::FetchImage => self.install_fetch_image(state, payload),
        }
    }
}

impl Installer {
    fn install_fetch_image(&self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
        match state {
            State::Idle   => Ok(None),
            State::Ready  => Ok(None),
            State::Verify => Ok(None),
            State::Fetch  => self.step_image_writer(payload),
            State::Commit => self.step_report(InstallOutcome::ok()),
            State::Abort  => self.step_report(InstallOutcome::error("aborted".into()))
        }
    }

    fn step_image_writer(&self, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
        match payload {
            Some(Payload::ImageMeta(bytes)) => {
                let meta: ImageMeta = json::from_slice(&bytes)?;
                fs::create_dir_all(IMAGE_DIR)?;
                Ok(Some(StepData::ImageWriter(ImageWriter::new(meta, IMAGE_DIR.into())?)))
            }
            _ => Err(Error::Image(format!("unexpected image_writer payload data: {:?}", payload)))
        }
    }

    fn step_report(&self, outcome: InstallOutcome) -> Result<Option<StepData>, Error> {
        let custom = EcuCustom::from_result(outcome.into_result(self.serial.clone()));
        let image = TufImage {
            filepath: "<undefined>".into(),
            fileinfo: TufMeta {
                length: 0,
                hashes: hashmap!{ "sha256".into() => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into() },
                custom: None,
            }
        };
        let version = self.to_version(image, Some(custom));
        let report = self.private_key.sign_data(json::to_value(version)?, self.sig_type)?;
        Ok(Some(StepData::TufReport(report)))
    }

    fn to_version(&self, image: TufImage, custom: Option<EcuCustom>) -> EcuVersion {
        EcuVersion {
            attacks_detected: "".into(),
            custom: custom,
            ecu_serial: self.serial.clone(),
            installed_image: image,
            previous_timeserver_time: "1970-01-01T00:00:00Z".into(),
            timeserver_time: "1970-01-01T00:00:00Z".into(),
        }
    }
}
