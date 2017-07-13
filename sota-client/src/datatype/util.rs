use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use datatype::Error;


pub struct Util;

impl Util {
    pub fn read_file(path: &str) -> Result<Vec<u8>, Error> {
        trace!("reading file: {}", path);
        let mut file = BufReader::new(File::open(path)
            .map_err(|err| Error::Client(format!("couldn't open {}: {}", path, err)))?);
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|err| Error::Client(format!("couldn't read {}: {}", path, err)))?;
        Ok(buf)
    }

    pub fn read_text(path: &str) -> Result<String, Error> {
        trace!("reading text from file: {}", path);
        let mut file = BufReader::new(File::open(path)
            .map_err(|err| Error::Client(format!("couldn't open {}: {}", path, err)))?);
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|err| Error::Client(format!("couldn't read {}: {}", path, err)))?;
        Ok(text)
    }

    pub fn write_file(file_path: &str, buf: &[u8]) -> Result<(), Error> {
        trace!("writing to file: {}", file_path);
        let path = Path::new(file_path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|err| Error::Client(format!("couldn't open {} for writing: {}", file_path, err)))?;
        let _ = file.write(buf)
            .map_err(|err| Error::Client(format!("couldn't write to {}: {}", file_path, err)))?;
        file.flush()?;
        Ok(())
    }
}
