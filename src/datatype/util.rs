use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};

use datatype::Error;


pub struct Util;

impl Util {
    pub fn read_file(path: &str) -> Result<Vec<u8>, Error> {
        let mut file = BufReader::new(File::open(path)
            .map_err(|err| Error::Client(format!("couldn't open {}: {}", path, err)))?);
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|err| Error::Client(format!("couldn't read {}: {}", path, err)))?;
        Ok(buf)
    }

    pub fn write_file(path: &str, buf: &[u8]) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|err| Error::Client(format!("couldn't open {} for writing: {}", path, err)))?;
        let _ = file.write(buf)
            .map_err(|err| Error::Client(format!("couldn't write to {}: {}", path, err)))?;
        file.flush()?;
        Ok(())
    }
}
