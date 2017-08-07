use json;
use std::fs;

use config::*;
use sota::datatype::{EcuVersion, OstreePackage, SignatureType, TufImage, TufMeta, Util};


pub struct Manifests;

impl Manifests {
    pub fn generate_all(priv_keys_dir: &str) -> Result<()> {
        for entry in fs::read_dir(&priv_keys_dir)? {
            if let Some(file) = entry.ok().and_then(|e| e.path().file_name().and_then(|n| n.to_str()).map(|n| String::from(n))) {
                let tokens = file.split(".der").collect::<Vec<_>>();
                if tokens.len() == 2 {
                    let serial = tokens[0];
                    debug!("DER key found for {}", serial);
                    let version = EcuVersion::from(serial.into(), Self::tuf_image(serial)?, None);
                    let signed = SignatureType::RsaSsaPss.sign_manifest(version, &format!("{}/{}", priv_keys_dir, file))?;
                    Util::write_file(&format!("{}/{}.manifest", priv_keys_dir, serial), &json::to_vec(&signed)?)?;
                }
            }
        }
        Ok(())
    }

    fn tuf_image(serial: &str) -> Result<TufImage> {
        let current = OstreePackage::get_current(serial)?;
        Ok(TufImage {
            filepath: current.commit.clone(),
            fileinfo: TufMeta {
                length: 0,
                hashes: hashmap!{ "sha256".into() => current.commit },
                custom: None,
            }
        })
    }
}
