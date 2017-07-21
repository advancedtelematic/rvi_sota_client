use json;
use std::fs;

use config::*;
use sota::datatype::{EcuVersion, SignatureType, TufImage, TufMeta, Util};


pub struct Manifests;

impl Manifests {
    pub fn generate_all(priv_keys_dir: &str) -> Result<()> {
        for entry in fs::read_dir(&priv_keys_dir)? {
            if let Some(file) = entry.ok().and_then(|e| e.path().file_name().and_then(|n| n.to_str()).map(|n| String::from(n))) {
                let tokens = file.split(".der").collect::<Vec<_>>();
                if tokens.len() == 2 {
                    let serial = tokens[0];
                    debug!("DER key found for {}", serial);
                    let version = EcuVersion::from(serial.into(), Self::new_tuf_image(), None);
                    let signed = SignatureType::RsaSsaPss.sign_manifest(version, &format!("{}/{}", priv_keys_dir, file))?;
                    Util::write_file(&format!("{}/{}.manifest", priv_keys_dir, serial), &json::to_vec(&signed)?)?;
                }
            }
        }
        Ok(())
    }

    fn new_tuf_image() -> TufImage {
        TufImage {
            filepath: "<undefined>".into(),
            fileinfo: TufMeta {
                length: 0,
                hashes: hashmap!{ "sha256".into() => "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into() },
                custom: None,
            }
        }
    }
}
