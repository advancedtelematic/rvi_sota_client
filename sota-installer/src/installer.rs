use json;
use std::fs;

use sota::atomic::{Payload, State, Step, StepData};
use sota::images::{ImageMeta, ImageWriter};
use sota::datatype::{EcuCustom, EcuVersion, Error, InstallOutcome, PrivateKey,
                     SignatureType, TufImage, TufMeta};


#[derive(PartialEq, Clone, Debug)]
pub enum InstallType {
    Overwrite { image_path: String },
}


/// An `Installer` will delegate at each `State` transition to a function that
/// will take the appropriate action based on the `InstallType`.
pub struct Installer {
    pub serial: String,
    pub install_type: InstallType,
    pub private_key: PrivateKey,
    pub sig_type: SignatureType,

    pub image_dir: String,
    pub filepath: Option<String>,
}

impl Step for Installer {
    fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
        match self.install_type {
            InstallType::Overwrite { image_path: ref to } => {
                match state {
                    State::Idle   => Ok(None),
                    State::Ready  => Ok(None),
                    State::Verify => Ok(None),
                    State::Fetch  => {
                        if let Some(Payload::ImageMeta(bytes)) = payload {
                            let meta: ImageMeta = json::from_slice(&bytes)?;
                            self.filepath = Some(meta.image_name.clone());
                            Ok(Some(StepData::ImageWriter(ImageWriter::new(meta, self.image_dir.clone()))))
                        } else {
                            Err(Error::Image(format!("unexpected image_writer payload data: {:?}", payload)))
                        }
                    },
                    State::Commit => {
                        let from = format!("{}/{}", self.image_dir, self.filepath.as_ref().expect("filepath"));
                        fs::copy(&from, to)?;
                        fs::remove_file(from)?;
                        self.step_report(InstallOutcome::ok())
                    },
                    State::Abort => self.step_report(InstallOutcome::error("aborted".into()))
                }
            },
        }
    }
}

impl Installer {
    fn step_report(&self, outcome: InstallOutcome) -> Result<Option<StepData>, Error> {
        let custom = EcuCustom::from_result(outcome.into_result(self.serial.clone()));
        let image = TufImage {
            filepath: if let Some(ref path) = self.filepath { path.clone() } else { "<unknown>".into() },
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
