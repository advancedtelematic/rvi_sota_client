use std::fmt::{self, Display, Formatter};


#[derive(Debug)]
pub enum Error {
    Cookie(String)
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let text: String = match *self {
            Error::Cookie(ref s) => format!("reading cookie: {}", s)
        }
        write!(f, "{}", text)
    }
}
