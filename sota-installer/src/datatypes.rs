use std::fs::File;
use std::io::Read;

use sota::datatype::Error;


pub struct Text;

impl Text {
    pub fn read(path: &str) -> Result<String, Error> {
        let mut file = File::open(path)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
    }
}
