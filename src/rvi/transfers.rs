use base64;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use std::fs;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::str::FromStr;
use std::vec::Vec;
use time;
use uuid::Uuid;


/// All currently active transfers.
pub struct Transfers {
    items:       HashMap<Uuid, Transfer>,
    storage_dir: String
}

impl Transfers {
    pub fn new(storage_dir: String) -> Transfers {
        Transfers { items: HashMap::new(), storage_dir: storage_dir }
    }

    pub fn get(&self, update_id: Uuid) -> Option<&Transfer> {
        self.items.get(&update_id)
    }

    pub fn get_mut(&mut self, update_id: Uuid) -> Option<&mut Transfer> {
        self.items.get_mut(&update_id)
    }

    pub fn push(&mut self, update_id: Uuid, checksum: String) {
        self.items.insert(update_id, Transfer::new(self.storage_dir.to_string(), update_id, checksum));
    }

    pub fn remove(&mut self, update_id: &Uuid) {
        self.items.remove(update_id);
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn prune(&mut self, now: i64, timeout: i64) {
        let old = self.items
            .iter()
            .filter(|&(_, transfer)| now - transfer.last_chunk_received > timeout)
            .map(|(id, _)| *id)
            .collect::<Vec<Uuid>>();

        for id in &old {
            info!("Transfer for update_id {} timed out.", id);
            self.remove(id);
        }
    }
}


/// Holds the details of the transferred chunks relating to an `Uuid`.
pub struct Transfer {
    pub update_id:           Uuid,
    pub checksum:            String,
    pub transferred_chunks:  Vec<u64>,
    pub storage_dir:         String,
    pub last_chunk_received: i64
}

impl Transfer {
    /// Prepare for the transfer of a new package.
    pub fn new(storage_dir: String, update_id: Uuid, checksum: String) -> Transfer {
        Transfer {
            update_id:           update_id,
            checksum:            checksum,
            transferred_chunks:  Vec::new(),
            storage_dir:         storage_dir,
            last_chunk_received: time::get_time().sec
        }
    }

    /// Write the received chunk to disk and store metadata inside `Transfer`.
    pub fn write_chunk(&mut self, data: &str, index: u64) -> Result<(), String> {
        self.last_chunk_received = time::get_time().sec;
        let mut path = self.get_chunk_dir().map_err(|err| format!("couldn't get chunk dir: {}", err))?;
        path.push(index.to_string());
        let mut file = File::create(path).map_err(|err| format!("couldn't open chunk file: {}", err))?;
        file.write_all(&base64::decode(data).map_err(|err| format!("couldn't decode chunk {}: {}", index, err))?)
            .map_err(|err| format!("couldn't write chunk {} for update_id {}: {}", index, self.update_id, err))?;
        file.flush().map_err(|err| format!("couldn't flush file: {}", err))?;

        self.transferred_chunks.push(index);
        self.transferred_chunks.sort();
        self.transferred_chunks.dedup();
        Ok(())
    }

    /// Assemble all received chunks into a complete package.
    pub fn assemble_package(&self) -> Result<PathBuf, String> {
        debug!("finalizing package {}", self.update_id);
        self.assemble_chunks()?;
        self.verify()
            .and_then(|_| self.get_package_path())
            .map_err(|err| format!("couldn't assemble_package for update_id {}: {}", self.update_id, err))
    }

    fn assemble_chunks(&self) -> Result<(), String> {
        let pkg_path = self.get_package_path()?;
        debug!("saving update_id {} to {}", self.update_id, pkg_path.display());
        let mut file = File::create(pkg_path).map_err(|err| format!("couldn't open package file: {}", err))?;

        let chunk_dir = self.get_chunk_dir()?;
        let entries   = fs::read_dir(chunk_dir.clone()).map_err(|err| format!("couldn't read dir: {}", err))?;
        let mut indices = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|err| format!("bad entry: {}", err))?;
            let name  = entry.file_name().into_string().map_err(|err| format!("bad entry name: {:?}", err))?;
            let index = u64::from_str(&name).map_err(|err| format!("couldn't parse chunk index: {}", err))?;
            indices.push(index);
        }
        indices.sort();

        for index in indices {
            self.append_chunk(&mut file, chunk_dir.clone(), index)?;
        }
        Ok(debug!("assembled chunks for update_id {}", self.update_id))
    }

    fn append_chunk(&self, file: &mut File, mut chunk_dir: PathBuf, index: u64) -> Result<(), String> {
        chunk_dir.push(&index.to_string());
        let mut chunk = File::open(chunk_dir).map_err(|err| format!("couldn't open chunk: {}", err))?;
        let mut buf = Vec::new();
        chunk.read_to_end(&mut buf).map_err(|err| format!("couldn't read file {}: {}", index, err))?;
        file.write(&buf).map_err(|err| format!("couldn't write chunk {}: {}", index, err))?;
        Ok(trace!("wrote chunk {} for update_id {}", index, self.update_id))
    }

    fn verify(&self) -> Result<(), String> {
        let path = self.get_package_path()?;
        let mut file = File::open(path).map_err(|err| format!("couldn't open package path: {}", err))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|err| format!("couldn't read file: {}", err))?;

        let mut hash = Sha1::new();
        hash.input(&data);
        if hash.result_str() != self.checksum {
            Err(format!("update_id {} checksum failed: expected {}, got {}", self.update_id, self.checksum, hash.result_str()))
        } else {
            Ok(())
        }
    }

    fn get_chunk_dir(&self) -> Result<PathBuf, String> {
        let mut path = PathBuf::from(&self.storage_dir);
        path.push("downloads");
        path.push(format!("{}", self.update_id));
        fs::create_dir_all(&path)
           .map(|_| path)
           .map_err(|err| format!("couldn't create chunk dir: {}", err))
    }

    fn get_package_path(&self) -> Result<PathBuf, String> {
        let mut path = PathBuf::from(&self.storage_dir);
        path.push("packages");
        fs::create_dir_all(&path).map_err(|err| format!("couldn't create package dir {:?}: {}", path, err))?;
        path.push(format!("{}.spkg", self.update_id));
        Ok(path)
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        let _ = self.get_chunk_dir().map(|dir| {
            fs::read_dir(&dir)
                .or_else(|err| Err(error!("couldn't read dir {:?}: {}", &dir, err)))
                .map(|entries| for entry in entries { let _ = entry.map(|entry| fs::remove_file(entry.path())); })
                .and_then(|_| fs::remove_dir(dir).map_err(|err| error!("couldn't remove dir: {}", err)))
        });
    }
}


#[cfg(test)]
mod test {
    use super::*;

    use base64;
    use std::path::PathBuf;
    use std::fs::File;
    use time;

    use pacman::test::TestDir;


    impl Transfer {
        pub fn new_test(test_dir: &TestDir) -> Transfer {
            Transfer {
                update_id:           Uuid::new_v4(),
                checksum:            "".to_string(),
                transferred_chunks:  Vec::new(),
                storage_dir:         test_dir.0.clone(),
                last_chunk_received: time::get_time().sec
            }
        }

        pub fn assert_chunk_written(&mut self, test_dir: &TestDir, index: u64, data: &[u8]) {
            self.write_chunk(&base64::encode_config(data, base64::URL_SAFE_NO_PAD), index).expect("write chunk");
            let mut file = File::open(&format!("{}/downloads/{}/{}", test_dir.0.clone(), self.update_id, index)).expect("open file");
            let mut buf  = Vec::new();
            let _        = file.read_to_end(&mut buf).expect("read file");
            assert_eq!(data.to_vec(), buf);
        }
    }


    #[test]
    fn test_package_directory_created() {
        let test_dir  = TestDir::new("sota-test-transfers");
        let transfer  = Transfer::new_test(&test_dir);
        let chunk_dir = transfer.get_package_path().unwrap();
        let path      = format!("{}/packages/{}.spkg", test_dir.0, transfer.update_id);
        assert_eq!(chunk_dir.to_str().unwrap(), path);
    }

    #[test]
    fn test_checksum() {
        let test_dir     = TestDir::new("sota-test-transfers");
        let mut transfer = Transfer::new_test(&test_dir);
        transfer.assert_chunk_written(&test_dir, 0, "test\n".to_string().as_bytes());
        transfer.assemble_chunks().expect("couldn't assemble chunks");

        transfer.checksum = "4e1243bd22c66e76c2ba9eddc1f91394e57f9f83".to_string();
        assert!(transfer.verify().is_ok());

        transfer.checksum = "invalid".to_string();
        assert!(transfer.verify().is_err());
    }

    #[test]
    fn test_assemble_chunks() {
        let test_dir     = TestDir::new("sota-test-transfers");
        let mut transfer = Transfer::new_test(&test_dir);
        let mut assembly = String::new();
        for index in 1..20 {
            let data = format!("{}", time::precise_time_ns());
            assembly.push_str(&format!("{}", data));
            transfer.assert_chunk_written(&test_dir, index as u64, data.as_bytes());
        }

        transfer.assemble_chunks().expect("couldn't assemble chunks");
        let path    = format!("{}/packages/{}.spkg", test_dir.0, transfer.update_id);
        let mut buf = Vec::new();
        let _       = File::open(PathBuf::from(path)).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(assembly.into_bytes(), buf);
    }
}
