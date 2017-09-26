use json;
use std::fs;
use std::path::Path;

use sota::atomic::{Payload, State, Step, StepData};
use sota::images::{ImageMeta, ImageWriter};
use sota::datatype::{EcuCustom, EcuVersion, Error, InstallOutcome, PrivateKey,
                     SignatureType, TufImage, TufMeta};


#[derive(PartialEq, Clone, Debug)]
pub enum InstallType {
    Overwrite { output_dir: String },
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
    pub meta: Option<ImageMeta>,
}

impl Step for Installer {
    fn step(&mut self, state: State, payload: Option<Payload>) -> Result<Option<StepData>, Error> {
        match self.install_type {
            InstallType::Overwrite { ref output_dir } => {
                match state {
                    State::Idle   |
                    State::Start  |
                    State::Verify => Ok(None),

                    State::Fetch => {
                        if let Some(Payload::ImageMeta(bytes)) = payload {
                            let meta: ImageMeta = json::from_slice(&bytes)?;
                            self.meta = Some(meta.clone());
                            self.filepath = Some(meta.image_name.clone());
                            Ok(Some(StepData::ImageWriter(ImageWriter::new(meta, self.image_dir.clone()))))
                        } else {
                            Err(Error::Image(format!("unexpected image_writer payload data: {:?}", payload)))
                        }
                    }

                    State::Commit => {
                        let name = self.filepath.as_ref().expect("filepath");
                        let from = format!("{}/{}", self.image_dir, name);
                        let to = format!("{}/{}", output_dir, name);
                        if let Some(parent) = Path::new(&to).parent() {
                            fs::create_dir_all(parent)?;
                        }
                        fs::copy(&from, &to)?;
                        fs::remove_file(&from)?;
                        self.step_report(InstallOutcome::ok())
                    }

                    State::Abort => self.step_report(InstallOutcome::error("aborted".into()))
                }
            },
        }
    }
}

impl Installer {
    fn step_report(&self, outcome: InstallOutcome) -> Result<Option<StepData>, Error> {
        let (len, sha) = if let Some(ref meta) = self.meta {
            (meta.image_size, meta.sha256sum.clone())
        } else {
            (0, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into())
        };
        let image = TufImage {
            filepath: if let Some(ref path) = self.filepath { path.clone() } else { "<unknown>".into() },
            fileinfo: TufMeta {
                length: len,
                hashes: hashmap!{ "sha256".into() => sha },
                custom: None,
            }
        };

        let custom = EcuCustom::from_result(outcome.into_result(self.serial.clone()));
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
