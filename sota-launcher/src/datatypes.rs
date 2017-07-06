use std::fmt::{self, Display, Formatter};
use std::str::FromStr;


#[derive(Debug)]
pub enum Error {
    Cookie(String)
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let text = match *self {
            Error::Cookie(ref s) => format!("reading cookie: {}", s)
        };
        write!(f, "{}", text)
    }
}


#[derive(Serialize, Deserialize)]
pub struct Update {
    hardware_id: String,
    to: Target
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize)]
pub struct Target {
    target: String,
    checksum: Checksum,
    targetLength: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Checksum {
    method: String,
    hash: String,
}


#[derive(Clone, Debug, PartialEq)]
pub struct PlayCookie {
    session: String,
    access_token: String,
    auth_plus_token: String,
    csrf_token: String,
    namespace: String,
}

impl FromStr for PlayCookie {
    type Err = Error;

    fn from_str(session: &str) -> Result<PlayCookie, Error> {
        info!("Parsing PLAY_SESSION cookie...");
        let cookie = session.trim().splitn(2, '=').collect::<Vec<_>>();
        if cookie[0] != "PLAY_SESSION" {
            return Err(Error::Cookie(format!("expected cookie 'PLAY_SESSION', got '{}'", cookie[0])))
        }

        let parts = cookie[1].split('&').collect::<Vec<_>>();
        let session = parts[0];
        let access_token = parts[1].split('=').collect::<Vec<_>>();
        let auth_plus_token = parts[2].split('=').collect::<Vec<_>>();
        let csrf_token = parts[3].split('=').collect::<Vec<_>>();
        let namespace = parts[4].split('=').collect::<Vec<_>>();

        if access_token[0] != "access_token" {
            return Err(Error::Cookie(format!("expected key 'access_token', got '{}'", access_token[0])))
        } else if auth_plus_token[0] != "auth_plus_access_token" {
            return Err(Error::Cookie(format!("expected key 'auth_plus_access_token', got '{}'", auth_plus_token[0])))
        } else if csrf_token[0] != "csrfToken" {
            return Err(Error::Cookie(format!("expected key 'csrfToken', got '{}'", csrf_token[0])))
        } else if namespace[0] != "namespace" {
            return Err(Error::Cookie(format!("expected key 'namespace', got '{}'", namespace[0])))
        }

        Ok(PlayCookie {
            session: session.into(),
            access_token: access_token[1].into(),
            auth_plus_token: auth_plus_token[1].into(),
            csrf_token: csrf_token[1].into(),
            namespace: namespace[1].into(),
        })
    }
}

impl Display for PlayCookie {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PLAY_SESSION={}&access_token={}&auth_plus_access_token={}&csrfToken={}&namespace={}",
               self.session, self.access_token, self.auth_plus_token, self.csrf_token, self.namespace)
    }
}


#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;

    const COOKIE: &'static str = "\n\t PLAY_SESSION=1234567890abcdef1234567890abcdef12345678-id_token=1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABC.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG&access_token=abcdefghijklmnop&auth_plus_access_token=1234567890abcdefghijklmnopqrstuvwxy.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG&csrfToken=1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678&namespace=auth0%7C1234567890abcdefghijklmn";


    #[test]
    fn parse_cookie() {
        let cookie = COOKIE.parse::<PlayCookie>().expect("parse");
        assert_eq!(&cookie.session, "1234567890abcdef1234567890abcdef12345678-id_token=1234567890abcdefghijklmnopqrstuvwxyz.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABC.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG");
        assert_eq!(&cookie.access_token, "abcdefghijklmnop");
        assert_eq!(&cookie.auth_plus_token, "1234567890abcdefghijklmnopqrstuvwxy.1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn.1234567890abcdefghijklmnopqrstuvwxyzABCDEFG");
        assert_eq!(&cookie.csrf_token, "1234567890abcdef1234567890abcdef12345678-1234567890123-1234567890abcdef12345678");
        assert_eq!(&cookie.namespace, "auth0%7C1234567890abcdefghijklmn");
        assert_eq!(format!("{}", cookie), COOKIE.trim());
    }
}
